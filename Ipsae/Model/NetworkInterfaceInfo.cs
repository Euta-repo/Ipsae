namespace Ipsae.Model;

/// <summary>
/// 네트워크 인터페이스 정보 (설정 드롭다운용)
/// </summary>
public class NetworkInterfaceInfo
{
    /// <summary>
    /// 인터페이스 이름 (예: "Ethernet", "Wi-Fi")
    /// INI 설정 파일의 Interface= 값으로 사용됨
    /// "auto"인 경우 Primary NIC 자동 감지
    /// </summary>
    public string Name { get; set; } = "";

    /// <summary>
    /// 표시용 설명 (예: "Auto (Ethernet - 192.168.0.5)", "Wi-Fi - 10.0.0.2")
    /// </summary>
    public string DisplayName { get; set; } = "";

    /// <summary>
    /// IPv4 주소 (없으면 빈 문자열)
    /// </summary>
    public string IpAddress { get; set; } = "";

    /// <summary>
    /// Auto 항목인지 여부
    /// </summary>
    public bool IsAuto { get; set; }
}
