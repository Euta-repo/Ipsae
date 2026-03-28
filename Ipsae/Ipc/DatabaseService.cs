using Ipsae.Model;
using IpsaeShared;
using Microsoft.Data.Sqlite;
using Serilog;
using System.Net;
using System.Net.Http;

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
            
            CREATE UNIQUE INDEX IF NOT EXISTS idx_threat_host_ip 
            ON tb_threat_host(host_ip, host_type);
            """;
        command.ExecuteNonQuery();
    }
}


public class ThreatFeedImporter
{
    private static readonly HttpClient _http = new HttpClient
    {
        Timeout = TimeSpan.FromSeconds(30)
    };

    // source 이름, URL, threat_level (0~100)
    private static readonly List<(string Source, string Url, int ThreatLevel)> Feeds =
    [
        ("spamhaus_drop",       "https://www.spamhaus.org/drop/drop.txt",                                         80),
        ("spamhaus_edrop",      "https://www.spamhaus.org/drop/edrop.txt",                                        80),
        ("feodo_botnet",        "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",                        90),
        ("emerging_threats",    "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",               70),
        ("cins_score",          "http://cinsscore.com/list/ci-badguys.txt",                                       70),
        ("firehol_level1",      "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset", 60),
    ];

    public async Task RunAsync()
    {
        Log.Information("[ThreatFeed] 업데이트 시작");

        foreach (var (source, url, threatLevel) in Feeds)
        {
            Log.Information("[ThreatFeed] {Source} 다운로드 중...", source);
            try
            {
                var ips = await FetchIpsAsync(url);
                Log.Information("[ThreatFeed] {Source} {Count}개 수집", source, ips.Count);

                int inserted = 0, updated = 0;
                using var connection = DatabaseService.Instance.CreateConnection();

                foreach (var ip in ips)
                {
                    var result = UpsertThreatIp(connection, ip, source, threatLevel);
                    if (result == UpsertResult.Inserted) inserted++;
                    else if (result == UpsertResult.Updated) updated++;
                }

                Log.Information("[ThreatFeed] {Source} 완료 - 신규:{Inserted} 업데이트:{Updated}",
                    source, inserted, updated);
            }
            catch (Exception ex)
            {
                Log.Error(ex, "[ThreatFeed] {Source} 실패", source);
            }
        }

        Log.Information("[ThreatFeed] 업데이트 완료");
    }

    // IP 문자열 → uint (정수) 변환
    private static uint IpToInt(string ipStr)
    {
        if (!IPAddress.TryParse(ipStr, out var addr))
            throw new FormatException($"잘못된 IP: {ipStr}");

        var bytes = addr.GetAddressBytes(); // big-endian
        return ((uint)bytes[0] << 24)
             | ((uint)bytes[1] << 16)
             | ((uint)bytes[2] << 8)
             | (uint)bytes[3];
    }

    private enum UpsertResult { Inserted, Updated, Skipped }

    private UpsertResult UpsertThreatIp(SqliteConnection connection, string ip, string source, int threatLevel)
    {
        uint ipInt;
        try { ipInt = IpToInt(ip); }
        catch { return UpsertResult.Skipped; } // CIDR 등 파싱 불가한 라인 스킵

        long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();

        using var cmd = connection.CreateCommand();

        // 이미 있으면 last_date, threat_level 업데이트
        cmd.CommandText = """
            INSERT INTO tb_threat_host
                (host_type, host_ip, host_domain, source, is_valid, create_date, last_date, threat_level)
            VALUES
                (0, $ip, '', $source, 1, $now, $now, $level)
            ON CONFLICT DO NOTHING
            """;
        cmd.Parameters.AddWithValue("$ip", (long)ipInt); // SQLite는 unsigned 없으므로 long
        cmd.Parameters.AddWithValue("$source", source);
        cmd.Parameters.AddWithValue("$now", now);
        cmd.Parameters.AddWithValue("$level", threatLevel);

        int rows = cmd.ExecuteNonQuery();
        if (rows > 0) return UpsertResult.Inserted;

        // 이미 존재 → last_date, threat_level 갱신
        cmd.CommandText = """
            UPDATE tb_threat_host
            SET last_date    = $now,
                threat_level = MAX(threat_level, $level),
                is_valid     = 1
            WHERE host_ip = $ip AND host_type = 0
            """;
        cmd.ExecuteNonQuery();
        return UpsertResult.Updated;
    }

    private static async Task<List<string>> FetchIpsAsync(string url)
    {
        var ips = new List<string>();
        var response = await _http.GetStringAsync(url);

        foreach (var raw in response.Split('\n'))
        {
            var line = raw.Trim();

            // 주석/빈줄 스킵
            if (string.IsNullOrEmpty(line) || line.StartsWith('#') || line.StartsWith(';'))
                continue;

            // "1.2.3.4 ; comment" 같은 형식 처리
            var ip = line.Split([' ', '\t', ';'], StringSplitOptions.RemoveEmptyEntries)[0];

            // CIDR 포함 라인은 스킵 (순수 IP만)
            if (ip.Contains('/')) continue;

            ips.Add(ip);
        }

        return ips;
    }

    // tb_threat_host에서 IP 조회 (uint 기준)
    public bool IsThreat(string ipStr)
    {
        if (!IPAddress.TryParse(ipStr, out _)) return false;
        uint ipInt = IpToInt(ipStr);

        using var connection = DatabaseService.Instance.CreateConnection();
        using var cmd = connection.CreateCommand();
        cmd.CommandText = """
            SELECT COUNT(*) FROM tb_threat_host
            WHERE host_ip = $ip AND host_type = 0 AND is_valid = 1
            """;
        cmd.Parameters.AddWithValue("$ip", (long)ipInt);
        return Convert.ToInt64(cmd.ExecuteScalar()) > 0;
    }
}