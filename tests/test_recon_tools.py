from analisis import AgenteReconocimiento


class FakeKali:
    def __init__(self, result):
        self.result = result
        self.commands = []

    def ejecutar_sudo(self, command):
        self.commands.append(command)
        return {"codigo_salida": 0, "resultado": self.result, "errores": ""}


def test_nmap_xml_is_converted_to_structured_inventory():
    xml = """<?xml version="1.0"?>
    <nmaprun>
      <host>
        <address addr="127.0.0.1" addrtype="ipv4" />
        <ports>
          <port protocol="tcp" portid="8080">
            <state state="open" />
            <service name="http" product="Lab server" version="1.0" method="probed" />
          </port>
        </ports>
      </host>
      <runstats><finished exit="success" /></runstats>
    </nmaprun>"""
    kali = FakeKali(xml)
    agent = object.__new__(AgenteReconocimiento)
    agent.kali = kali

    result = agent._nmap(
        {
            "host": "127.0.0.1",
            "ipv6": False,
            "puerto": 8080,
            "scheme": "http",
            "path": "/",
            "url": "http://127.0.0.1:8080/",
        }
    )

    port = result["hosts"][0]["puertos"][0]
    assert port == {
        "puerto": 8080,
        "protocolo": "tcp",
        "estado": "open",
        "servicio": "http",
        "producto": "Lab server",
        "version": "1.0",
        "metodo_identificacion": "probed",
    }
    assert kali.commands[0].startswith("nmap ")

