import os
import re
import shlex
import socket
import subprocess
import time

import paramiko
from dotenv import load_dotenv

from command_policy import validate_remote_command

load_dotenv()


class KaliSSHClient:

    def __init__(self):

        self.maquinas = [
            {
                "nombre": os.getenv("JUAN_VM_NAME"),
                "ip": os.getenv("JUAN_VM_IP"),
                "usuario": os.getenv("JUAN_VM_USER"),
                "password": os.getenv("JUAN_VM_PASSWORD"),
            },
            {
                "nombre": os.getenv("ANGEL_VM_NAME"),
                "ip": os.getenv("ANGEL_VM_IP"),
                "usuario": os.getenv("ANGEL_VM_USER"),
                "password": os.getenv("ANGEL_VM_PASSWORD"),
            }
        ]

        self.vboxmanage = os.getenv("VBOXMANAGE_PATH")
        self.cliente = None
        self.maquina_activa = None

    def encender_si_apagada(self, maquina):

        nombre = maquina["nombre"]

        if not self.vboxmanage:
            raise ValueError("VBOXMANAGE_PATH is not configured")

        resultado = subprocess.run(
            [
                self.vboxmanage,
                "showvminfo",
                nombre,
                "--machinereadable"
            ],
            capture_output=True,
            text=True,
            check=True,
            timeout=15
        )

        coincidencia = re.search(
            r'^VMState="([^"]+)"$',
            resultado.stdout,
            re.MULTILINE
        )

        if not coincidencia:
            raise RuntimeError(
                f"No se pudo obtener el estado de {nombre}"
            )

        estado = coincidencia.group(1)

        if estado == "running":
            print(f"{nombre} ya está encendida.")
            return

        if estado not in ("poweroff", "saved"):
            raise RuntimeError(
                f"No se puede iniciar {nombre}. Estado: {estado}"
            )

        print(f"Encendiendo {nombre}...")

        subprocess.run(
            [
                self.vboxmanage,
                "startvm",
                nombre,
                "--type",
                "headless"
            ],
            capture_output=True,
            text=True,
            check=True,
            timeout=60
        )

    def esperar_ssh(self, ip, timeout=180):

        print(f"Esperando que SSH esté disponible en {ip}...")

        inicio = time.monotonic()
        intento = 0

        while time.monotonic() - inicio < timeout:

            intento += 1

            try:
                with socket.create_connection(
                    (ip, 22),
                    timeout=3
                ):
                    print("SSH disponible. Kali está lista.")
                    return True

            except OSError:
                transcurrido = int(time.monotonic() - inicio)

                print(
                    f"Intento {intento}: "
                    f"Kali todavía no responde "
                    f"({transcurrido}s/{timeout}s)"
                )

                time.sleep(5)

        raise TimeoutError(
            f"SSH no está disponible en {ip} "
            f"después de {timeout} segundos"
    )

    def conectar(self):

        errores = []

        for maquina in self.maquinas:

            nombre = maquina["nombre"]
            cliente = None

            try:
                print(f"\nIntentando conectar con {nombre}")

                if not all(maquina.values()):
                    raise ValueError(
                        "Faltan datos en las variables de entorno"
                    )

                self.encender_si_apagada(maquina)
                self.esperar_ssh(maquina["ip"])

                cliente = paramiko.SSHClient()

                cliente.load_system_host_keys()

                cliente.set_missing_host_key_policy(
                    paramiko.RejectPolicy()
                )

                cliente.connect(
                    hostname=maquina["ip"],
                    username=maquina["usuario"],
                    password=maquina["password"],
                    port=22,
                    timeout=10,
                    auth_timeout=10,
                    look_for_keys=False,
                    allow_agent=False
                )

                self.cliente = cliente
                self.maquina_activa = maquina

                print(f"Conectado correctamente con {nombre}")

                return nombre

            except Exception as error:

                if cliente is not None:
                    cliente.close()

                mensaje = f"{nombre}: {error}"
                errores.append(mensaje)

                print(f"Falló la conexión con {nombre}")

        raise ConnectionError(
            "No fue posible conectar con ninguna máquina:\n"
            + "\n".join(errores)
        )

    def ejecutar_sudo(self, comando):

        if self.cliente is None:
            raise RuntimeError("No existe una conexión SSH")

        validate_remote_command(comando)

        timeout = int(os.getenv("SSH_COMMAND_TIMEOUT_SECONDS", "30"))
        if timeout < 1 or timeout > 120:
            raise ValueError("SSH_COMMAND_TIMEOUT_SECONDS must be between 1 and 120")

        comando_remoto = (
            "sudo -S -p '' -- bash -lc "
            + shlex.quote(comando)
        )

        stdin, stdout, stderr = self.cliente.exec_command(
            comando_remoto,
            timeout=timeout,
            get_pty=False
        )

        stdin.write(
            self.maquina_activa["password"] + "\n"
        )
        stdin.flush()
        stdin.channel.shutdown_write()

        resultado = stdout.read().decode(
            errors="replace"
        )

        errores = stderr.read().decode(
            errors="replace"
        )

        codigo = stdout.channel.recv_exit_status()

        return {
            "maquina": self.maquina_activa["nombre"],
            "comando": comando,
            "resultado": resultado,
            "errores": errores,
            "codigo_salida": codigo
        }

    def cerrar(self):

        if self.cliente is not None:
            self.cliente.close()
            self.cliente = None
            self.maquina_activa = None
