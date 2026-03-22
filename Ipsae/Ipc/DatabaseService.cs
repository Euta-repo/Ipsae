using Ipsae.Model;
using IpsaeShared;
using Microsoft.Data.Sqlite;
using Serilog;

namespace Ipsae.Ipc;

public class DatabaseService
{
    private static readonly Lazy<DatabaseService> _instance = new(() => new DatabaseService());
    public static DatabaseService Instance => _instance.Value;

    public static string DbPath => IpsaePaths.DbPath;

    private DatabaseService() { }

    public bool Initialize()
    {
        try
        {
            using var connection = new SqliteConnection($"Data Source={DbPath}");
            connection.Open();

            CreateTables(connection);

            Log.Information("Database initialized: {Path}", DbPath);
            return true;
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Database initialization failed");
            return false;
        }
    }

    public SqliteConnection CreateConnection()
    {
        var connection = new SqliteConnection($"Data Source={DbPath}");
        connection.Open();
        return connection;
    }

    // rule_type: 0=blacklist, 1=whitelist
    // rule_target: 0=ip, 1=proc, 2=port

    public List<IpEntry> GetBlacklistIps()
    {
        return GetIpRules(0);
    }

    public List<IpEntry> GetWhitelistIps()
    {
        return GetIpRules(1);
    }

    private List<IpEntry> GetIpRules(int ruleType)
    {
        var list = new List<IpEntry>();
        try
        {
            using var connection = CreateConnection();
            using var command = connection.CreateCommand();
            command.CommandText = """
                SELECT rule_value,
                       (SELECT COUNT(*) FROM tb_network_log WHERE remote_ip = CAST(rule_value AS INTEGER)) AS find_count
                FROM tb_user_rule
                WHERE rule_type = $ruleType AND rule_target = 0 AND is_valid = 1
                """;
            command.Parameters.AddWithValue("$ruleType", ruleType);

            using var reader = command.ExecuteReader();
            while (reader.Read())
            {
                list.Add(new IpEntry
                {
                    IpAddress = reader.GetString(0),
                    FindCount = reader.GetInt32(1)
                });
            }
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Failed to get IP rules (type={RuleType})", ruleType);
        }
        return list;
    }

    public bool AddIpRule(string ip, int ruleType, string? reason = null)
    {
        try
        {
            using var connection = CreateConnection();
            using var command = connection.CreateCommand();
            command.CommandText = """
                INSERT INTO tb_user_rule (rule_type, rule_target, rule_value, rule_reason, is_valid, timestamp)
                VALUES ($ruleType, 0, $ip, $reason, 1, strftime('%s', 'now'))
                """;
            command.Parameters.AddWithValue("$ruleType", ruleType);
            command.Parameters.AddWithValue("$ip", ip);
            command.Parameters.AddWithValue("$reason", reason ?? (object)DBNull.Value);

            command.ExecuteNonQuery();
            return true;
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Failed to add IP rule: {Ip} (type={RuleType})", ip, ruleType);
            return false;
        }
    }

    public bool RemoveIpRule(string ip, int ruleType)
    {
        try
        {
            using var connection = CreateConnection();
            using var command = connection.CreateCommand();
            command.CommandText = """
                DELETE FROM tb_user_rule
                WHERE rule_type = $ruleType AND rule_target = 0 AND rule_value = $ip
                """;
            command.Parameters.AddWithValue("$ruleType", ruleType);
            command.Parameters.AddWithValue("$ip", ip);

            command.ExecuteNonQuery();
            return true;
        }
        catch (Exception ex)
        {
            Log.Error(ex, "Failed to remove IP rule: {Ip} (type={RuleType})", ip, ruleType);
            return false;
        }
    }

    private static void CreateTables(SqliteConnection connection)
    {
        using var command = connection.CreateCommand();
        command.CommandText = """
            CREATE TABLE IF NOT EXISTS tb_threat_host (
                idx          INTEGER PRIMARY KEY AUTOINCREMENT,
                host_type    INTEGER NOT NULL DEFAULT 0,
                host_ip      INTEGER NOT NULL DEFAULT 0,
                host_domain  TEXT    NOT NULL DEFAULT '',
                source       TEXT    NOT NULL DEFAULT '',
                is_valid     INTEGER NOT NULL DEFAULT 1,
                create_date  INTEGER,
                last_date    INTEGER,
                threat_level INTEGER NOT NULL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS tb_network_log (
                idx         INTEGER PRIMARY KEY AUTOINCREMENT,
                direction   INTEGER NOT NULL,
                protocol    INTEGER NOT NULL,
                remote_ip   INTEGER NOT NULL,
                remote_port INTEGER NOT NULL,
                local_port  INTEGER NOT NULL,
                length      INTEGER NOT NULL,
                is_threat   INTEGER NOT NULL DEFAULT 0,
                timestamp   INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS tb_dns_log (
                idx         INTEGER PRIMARY KEY AUTOINCREMENT,
                domain      TEXT    NOT NULL DEFAULT '',
                resolved_ip INTEGER NOT NULL DEFAULT 0,
                timestamp   INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS tb_process_log (
                idx         INTEGER PRIMARY KEY AUTOINCREMENT,
                network_idx INTEGER NOT NULL,
                pid         INTEGER NOT NULL,
                ppid        INTEGER,
                proc_name   TEXT NOT NULL,
                proc_path   TEXT NOT NULL,
                proc_user   TEXT,
                proc_create INTEGER,
                timestamp   INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS tb_user_rule (
                idx          INTEGER PRIMARY KEY AUTOINCREMENT,
                rule_type    INTEGER NOT NULL DEFAULT 0,
                rule_target  INTEGER NOT NULL DEFAULT 0,
                rule_value   TEXT    NOT NULL,
                rule_reason  TEXT,
                is_valid     INTEGER NOT NULL DEFAULT 1,
                timestamp    INTEGER
            );
            """;
        command.ExecuteNonQuery();
    }
}
