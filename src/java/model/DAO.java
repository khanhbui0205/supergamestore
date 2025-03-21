package model;

import entity.User;
import entity.Game;
import entity.Order;
import entity.Category;
import entity.OrderDetail;
import java.io.UnsupportedEncodingException;
import java.math.BigDecimal;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.*;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

public class DAO implements DatabaseInfo {

//    public static Connection getConnect() {
//        try {
//            Class.forName(DRIVERNAME);
//            return DriverManager.getConnection(DBURL, USERDB, PASSDB);
//        } catch (ClassNotFoundException | SQLException e) {
//            System.out.println("❌ Lỗi kết nối CSDL: " + e);
//            return null;
//        }
//    }
    
    public static Connection getConnect() {
    try {
        Class.forName(DRIVERNAME);
        return DriverManager.getConnection(DBURL, USERDB, PASSDB);
    } catch (ClassNotFoundException e) {
        throw new RuntimeException("Database Driver not found: " + e.getMessage(), e);
    } catch (SQLException e) {
        throw new RuntimeException("Database connection failed: " + e.getMessage(), e);
    }
}


    public boolean updateUser(int userId, String username, String phone, String address, String password) {
        String sql = "UPDATE Users SET username = ?, phone = ?, address = ?, password = ? WHERE user_id = ?";
        try (Connection conn = getConnect(); PreparedStatement stmt = conn.prepareStatement(sql)) {

            stmt.setString(1, username);
            stmt.setString(2, phone);
            stmt.setString(3, address);
            stmt.setString(4, password);
            stmt.setInt(5, userId);

            return stmt.executeUpdate() > 0; // Trả về true nếu cập nhật thành công
        } catch (SQLException e) {
            System.out.println("❌ Lỗi cập nhật user: " + e.getMessage());
        }
        return false;
    }

    // Đăng ký tài khoản mới
    public static boolean registerUser(String username, String email, String password) throws UnsupportedEncodingException {
        Connection conn = null;
        PreparedStatement stmt = null;
        boolean success = false;

        try {
            conn = getConnect();

            // Mã hóa mật khẩu
            String hashedPassword = hashPassword(password);

            String sql = "INSERT INTO Users (username, email, password) VALUES (?, ?, ?)";
            stmt = conn.prepareStatement(sql);
            stmt.setString(1, username);
            stmt.setString(2, email);
            stmt.setString(3, hashedPassword);

            int rows = stmt.executeUpdate();
            success = (rows > 0);
        } catch (SQLException e) {
            e.printStackTrace();
        } finally {
            try {
                if (stmt != null) {
                    stmt.close();
                }
                if (conn != null) {
                    conn.close();
                }
            } catch (SQLException e) {
                e.printStackTrace();
            }
        }
        return success;
    }

    // Hash mật khẩu
    public static String hashPassword(String password) throws UnsupportedEncodingException {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hash = md.digest(password.getBytes("UTF-8"));
            return Base64.getEncoder().encodeToString(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Lỗi mã hóa mật khẩu", e);
        }
    }
//
//    // Đăng nhập
//    public User login(String email, String password) throws UnsupportedEncodingException {
//        String sql = "SELECT * FROM Users WHERE email = ? AND password = ?";
//        try (Connection conn = getConnect(); PreparedStatement stmt = conn.prepareStatement(sql)) {
//
//            String hashedPassword = hashPassword(password); // Mã hóa mật khẩu
//
//            stmt.setString(1, email);
//            stmt.setString(2, hashedPassword);
//
//            System.out.println("🔍 SQL: " + sql + " | Email: " + email + " | Hashed Password: " + hashedPassword);
//
//            ResultSet rs = stmt.executeQuery();
//            if (rs.next()) {
//                return new User(
//                        rs.getInt("user_id"),
//                        rs.getString("username"),
//                        rs.getString("email"),
//                        rs.getString("password"),
//                        rs.getString("role"),
//                        rs.getTimestamp("created_at")
//                );
//            }
//        } catch (SQLException e) {
//            System.out.println("❌ Lỗi đăng nhập: " + e.getMessage());
//        }
//        return null;
//    }

    public User login(String email, String password) throws UnsupportedEncodingException {
        String sql = "SELECT * FROM Users WHERE email = ?";

        try (Connection conn = getConnect(); PreparedStatement stmt = conn.prepareStatement(sql)) {
            stmt.setString(1, email);
            System.out.println("🔍 SQL: " + sql + " | Email: " + email);

            ResultSet rs = stmt.executeQuery();
            if (rs.next()) {
                String passwordInDB = rs.getString("password");
                String hashedInputPassword = hashPassword(password);

                // Kiểm tra mật khẩu trong DB có phải hash không
                if (isHashedPassword(passwordInDB)) {
                    if (hashedInputPassword.equals(passwordInDB)) {
                        return getUserFromResultSet(rs);
                    }
                } else {
                    // Nếu mật khẩu chưa hash, kiểm tra trực tiếp
                    if (password.equals(passwordInDB)) {
                        // Hash lại mật khẩu rồi cập nhật vào DB
                        updatePasswordToHashed(email, hashedInputPassword);
                        return getUserFromResultSet(rs);
                    }
                }
            }
        } catch (SQLException e) {
            System.out.println("❌ Lỗi đăng nhập: " + e.getMessage());
        }
        return null;
    }

// Hàm kiểm tra mật khẩu có phải là hash hay không (SHA-256 Base64 có 44 ký tự)
    private boolean isHashedPassword(String password) {
        return password.matches("^[A-Za-z0-9+/]{43}=$"); // Base64 của SHA-256 luôn có 44 ký tự
    }

// Hàm cập nhật mật khẩu đã hash vào database
    private void updatePasswordToHashed(String email, String hashedPassword) {
        String sql = "UPDATE Users SET password = ? WHERE email = ?";

        try (Connection conn = getConnect(); PreparedStatement stmt = conn.prepareStatement(sql)) {
            stmt.setString(1, hashedPassword);
            stmt.setString(2, email);
            stmt.executeUpdate();
            System.out.println("✅ Đã cập nhật mật khẩu thành hash cho tài khoản: " + email);
        } catch (SQLException e) {
            System.out.println("❌ Lỗi cập nhật mật khẩu: " + e.getMessage());
        }
    }

// Hàm lấy User từ ResultSet
    private User getUserFromResultSet(ResultSet rs) throws SQLException {
        return new User(
                rs.getInt("user_id"),
                rs.getString("username"),
                rs.getString("email"),
                rs.getString("password"),
                rs.getString("phone"), // Thêm phone
                rs.getString("address"), // Thêm address
                rs.getString("role"),
                rs.getTimestamp("created_at")
        );
    }

    // Lấy danh sách game
    public static List<Game> getAllGames() {
        List<Game> games = new ArrayList<>();
        String sql = "SELECT game_id, title, description, price, release_date, developer, publisher, genre, platform, stock, created_at, image_url FROM Games";

        try (Connection conn = getConnect(); PreparedStatement stmt = conn.prepareStatement(sql); ResultSet rs = stmt.executeQuery()) {

            while (rs.next()) {
                Game game = new Game(
                        rs.getInt("game_id"),
                        rs.getString("title"),
                        rs.getString("description"),
                        rs.getBigDecimal("price"),
                        rs.getDate("release_date"),
                        rs.getString("developer"),
                        rs.getString("publisher"),
                        rs.getString("genre"),
                        rs.getString("platform"),
                        rs.getInt("stock"),
                        rs.getTimestamp("created_at"),
                        rs.getString("image_url") // 🖼️ Lấy dữ liệu hình ảnh
                );
                games.add(game);
            }
        } catch (SQLException e) {
            System.err.println("❌ Lỗi lấy danh sách game: " + e.getMessage());
            e.printStackTrace();
        }
        return games;
    }

    public static Game getGameById(int gameId) {
        Game game = null;
        String sql = "SELECT game_id, title, description, price, release_date, "
                + "developer, publisher, genre, platform, stock, created_at, image_url "
                + "FROM Games WHERE game_id = ?";

        try (Connection conn = getConnect(); PreparedStatement stmt = conn.prepareStatement(sql)) {

            stmt.setInt(1, gameId);
            ResultSet rs = stmt.executeQuery();

            if (rs.next()) {
                game = new Game(
                        rs.getInt("game_id"),
                        rs.getString("title"),
                        rs.getString("description"),
                        rs.getBigDecimal("price"),
                        rs.getDate("release_date"),
                        rs.getString("developer"),
                        rs.getString("publisher"),
                        rs.getString("genre"),
                        rs.getString("platform"),
                        rs.getInt("stock"),
                        rs.getTimestamp("created_at"),
                        rs.getString("image_url")
                );
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return game;
    }

    public static List<Game> searchGames(String keyword) {
        List<Game> games = new ArrayList<>();
        String sql = "SELECT * FROM Games WHERE title LIKE ? OR genre LIKE ? OR platform LIKE ?";

        try (Connection conn = getConnect(); PreparedStatement stmt = conn.prepareStatement(sql)) {

            String searchPattern = "%" + keyword + "%";
            stmt.setString(1, searchPattern);
            stmt.setString(2, searchPattern);
            stmt.setString(3, searchPattern);

            ResultSet rs = stmt.executeQuery();
            while (rs.next()) {
                Game game = new Game(
                        rs.getInt("game_id"),
                        rs.getString("title"),
                        rs.getString("description"),
                        rs.getBigDecimal("price"), // 🔹 BigDecimal
                        rs.getDate("release_date"),
                        rs.getString("developer"),
                        rs.getString("publisher"),
                        rs.getString("genre"),
                        rs.getString("platform"),
                        rs.getInt("stock"),
                        rs.getTimestamp("created_at"), // 🔹 Timestamp
                        rs.getString("image_url") // 🖼️ Thêm hình ảnh game
                );
                games.add(game);
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return games;
    }

    public static void addGame(Game game) {
        String sql = "INSERT INTO Games (title, description, price, release_date, developer, publisher, genre, platform, stock, image_url) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
        try (Connection conn = getConnect(); PreparedStatement stmt = conn.prepareStatement(sql)) {

            stmt.setString(1, game.getTitle());
            stmt.setString(2, game.getDescription());
            stmt.setBigDecimal(3, game.getPrice());
            stmt.setDate(4, (Date) game.getReleaseDate());
            stmt.setString(5, game.getDeveloper());
            stmt.setString(6, game.getPublisher());
            stmt.setString(7, game.getGenre());
            stmt.setString(8, game.getPlatform());
            stmt.setInt(9, game.getStock());
            stmt.setString(10, game.getImageUrl()); // 🖼️ Lưu đường dẫn ảnh

            stmt.executeUpdate();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static boolean deleteGame(int gameId) {
        String sql = "DELETE FROM Games WHERE game_id = ?";
        try (Connection conn = getConnect(); PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setInt(1, gameId);
            return ps.executeUpdate() > 0;
        } catch (SQLException e) {
            e.printStackTrace();
            return false;
        }
    }

    public boolean updateGame(Game game) {
        String sql = "UPDATE Games SET title = ?, description = ?, price = ?, release_date = ?, "
                + "developer = ?, publisher = ?, genre = ?, platform = ?, stock = ?, image_url = ? "
                + "WHERE game_id = ?";

        try (Connection conn = getConnect(); PreparedStatement stmt = conn.prepareStatement(sql)) {

            stmt.setString(1, game.getTitle());
            stmt.setString(2, game.getDescription());
            stmt.setBigDecimal(3, game.getPrice());
            stmt.setDate(4, (Date) game.getReleaseDate());
            stmt.setString(5, game.getDeveloper());
            stmt.setString(6, game.getPublisher());
            stmt.setString(7, game.getGenre());
            stmt.setString(8, game.getPlatform());
            stmt.setInt(9, game.getStock());
            stmt.setString(10, game.getImageUrl());
            stmt.setInt(11, game.getGameId());

            int rowsUpdated = stmt.executeUpdate();
            return rowsUpdated > 0;
        } catch (SQLException e) {
            e.printStackTrace();
            return false;
        }
    }

    public List<User> getAllUsers() {
        List<User> list = new ArrayList<>();
        String query = "SELECT * FROM Users";

        try (Connection conn = getConnect(); PreparedStatement ps = conn.prepareStatement(query); ResultSet rs = ps.executeQuery()) {

            while (rs.next()) {
                list.add(new User(
                        rs.getInt("user_id"),
                        rs.getString("username"),
                        rs.getString("email"),
                        rs.getString("password"),
                        rs.getString("phone"),
                        rs.getString("address"),
                        rs.getString("role"),
                        rs.getTimestamp("created_at")
                ));
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return list;
    }

    public boolean deleteUser(int userId) {
        String query = "DELETE FROM Users WHERE user_id = ?";
        try (Connection conn = getConnect(); PreparedStatement ps = conn.prepareStatement(query)) {
            ps.setInt(1, userId);
            int rowsAffected = ps.executeUpdate();
            return rowsAffected > 0;
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return false;
    }

    public boolean updateUser(User user) {
        Connection conn = getConnect();
        if (conn == null) {
            System.out.println("⚠️ Database connection is NULL!");
            return false;
        }

        String sql = "UPDATE users SET username=?, email=?, password=?, phone=?, address=?, role=? WHERE user_Id=?";
        try (PreparedStatement stmt = conn.prepareStatement(sql)) {
            stmt.setString(1, user.getUsername());
            stmt.setString(2, user.getEmail());
            stmt.setString(3, user.getPassword());  // Nếu cần, có thể mã hóa mật khẩu
            stmt.setString(4, user.getPhone());
            stmt.setString(5, user.getAddress());
            stmt.setString(6, user.getRole());
            stmt.setInt(7, user.getUserId());

            int rowsUpdated = stmt.executeUpdate();
            return rowsUpdated > 0;
        } catch (SQLException e) {
            e.printStackTrace();
            return false;
        }
    }

    public User getUserById(int userId) {
        Connection conn = getConnect();
        if (conn == null) {
            System.out.println("⚠️ Database connection is NULL!");
            return null;
        }

        String sql = "SELECT * FROM users WHERE user_Id=?";
        try (PreparedStatement stmt = conn.prepareStatement(sql)) {
            stmt.setInt(1, userId);
            ResultSet rs = stmt.executeQuery();

            if (rs.next()) {
                return new User(
                        rs.getInt("user_Id"),
                        rs.getString("username"),
                        rs.getString("email"),
                        rs.getString("password"),
                        rs.getString("phone"),
                        rs.getString("address"),
                        rs.getString("role"),
                        rs.getTimestamp("created_At")
                );
            } else {
                System.out.println("⚠️ Không tìm thấy user với ID: " + userId);
                return null;
            }
        } catch (SQLException e) {
            e.printStackTrace();
            return null;
        }
    }

    public static List<Order> getOrdersByUserId(int userId) {
        List<Order> orders = new ArrayList<>();
        String sql = "SELECT * FROM Orders WHERE user_id = ? ORDER BY created_at DESC";

        try (Connection conn = getConnect(); PreparedStatement stmt = conn.prepareStatement(sql)) {
            stmt.setInt(1, userId);
            ResultSet rs = stmt.executeQuery();

            while (rs.next()) {
                orders.add(new Order(
                        rs.getInt("order_id"),
                        rs.getInt("user_id"),
                        rs.getBigDecimal("total_amount"),
                        rs.getString("status"),
                        rs.getTimestamp("created_at")
                ));
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return orders;
    }

    public static Order getOrderById(int orderId) {
        String sql = "SELECT * FROM Orders WHERE order_id = ?";
        try (Connection conn = getConnect(); PreparedStatement stmt = conn.prepareStatement(sql)) {
            stmt.setInt(1, orderId);
            ResultSet rs = stmt.executeQuery();

            if (rs.next()) {
                return new Order(
                        rs.getInt("order_id"),
                        rs.getInt("user_id"),
                        rs.getBigDecimal("total_amount"),
                        rs.getString("status"),
                        rs.getTimestamp("created_at")
                );
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public static List<OrderDetail> getOrderDetailsByOrderId(int orderId) {
        List<OrderDetail> orderDetails = new ArrayList<>();
        String sql = "SELECT od.*, g.title AS gameTitle FROM OrderDetails od "
                + "JOIN Games g ON od.game_id = g.game_id WHERE od.order_id = ?";

        try (Connection conn = getConnect(); PreparedStatement stmt = conn.prepareStatement(sql)) {
            stmt.setInt(1, orderId);
            ResultSet rs = stmt.executeQuery();

            while (rs.next()) {
                orderDetails.add(new OrderDetail(
                        rs.getInt("order_detail_id"),
                        rs.getInt("order_id"),
                        rs.getInt("game_id"),
                        rs.getInt("quantity"),
                        rs.getBigDecimal("price"),
                        rs.getString("gameTitle") // Thêm tên game
                ));
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return orderDetails;
    }

    // Thêm sản phẩm vào giỏ hàng
    public static boolean addToCart(int userId, int gameId, int quantity) {
        String sql = "INSERT INTO Cart (user_id, game_id, quantity) VALUES (?, ?, ?)";
        try (Connection conn = getConnect(); PreparedStatement stmt = conn.prepareStatement(sql)) {

            stmt.setInt(1, userId);
            stmt.setInt(2, gameId);
            stmt.setInt(3, quantity);
            return stmt.executeUpdate() > 0;
        } catch (SQLException e) {
            System.out.println("❌ Lỗi thêm vào giỏ hàng: " + e.getMessage());
        }
        return false;
    }

    // Xóa sản phẩm khỏi giỏ hàng
    public static boolean removeFromCart(int cartId) {
        String sql = "DELETE FROM Cart WHERE cart_id = ?";
        try (Connection conn = getConnect(); PreparedStatement stmt = conn.prepareStatement(sql)) {

            stmt.setInt(1, cartId);
            return stmt.executeUpdate() > 0;
        } catch (SQLException e) {
            System.out.println("❌ Lỗi xóa sản phẩm khỏi giỏ hàng: " + e.getMessage());
        }
        return false;
    }

    // Tạo đơn hàng
    public static boolean createOrder(int userId, double totalAmount) {
        String sql = "INSERT INTO Orders (user_id, total_amount, status) VALUES (?, ?, 'pending')";
        try (Connection conn = getConnect(); PreparedStatement stmt = conn.prepareStatement(sql)) {

            stmt.setInt(1, userId);
            stmt.setDouble(2, totalAmount);
            return stmt.executeUpdate() > 0;
        } catch (SQLException e) {
            System.out.println("❌ Lỗi tạo đơn hàng: " + e.getMessage());
        }
        return false;
    }
}
