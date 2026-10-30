
"""AI RECON AGENT V8 - Orquestador principal."""

from ssh_client import KaliSSHClient
from agenteAnalisis import AgenteOSINT
from analisis import AgenteReconocimiento
from scope import ScopePolicy


# ==================================================
# 1. MOSTRAR SECCIONES DEL INFORME
# ==================================================

def mostrar_seccion(titulo, elementos):

    print(f"\n========== {titulo} ==========\n")

    if not elementos:
        print("Sin resultados registrados.")
        return

    for numero, item in enumerate(elementos, 1):

        if isinstance(item, str):
            print(f"{numero}. {item}\n")
            continue

        if not isinstance(item, dict):
            print(f"{numero}. {item}\n")
            continue

        identificador = item.get("id")

        titulo_item = (
            item.get("titulo")
            or item.get("descripcion")
            or "Observación"
        )

        prefijo = (
            f"[{identificador}] "
            if identificador else ""
        )

        print(f"{numero}. {prefijo}{titulo_item}")

        campos = (
            ("descripcion", "Descripción"),
            ("tipo", "Tipo"),
            ("severidad", "Severidad"),
            ("estado", "Estado"),
            ("confianza", "Confianza"),
            ("fuente", "Fuente"),
            ("origen", "Origen"),
            ("verificacion_pendiente", "Verificación pendiente"),
            ("recomendacion", "Recomendación"),
            ("medida_defensiva", "Medida defensiva"),
        )

        for clave, etiqueta in campos:

            valor = item.get(clave)

            if valor and not (
                clave == "descripcion"
                and not item.get("titulo")
            ):
                print(f"   {etiqueta}: {valor}")

        referencias = item.get("evidencias", [])

        if isinstance(referencias, list) and referencias:

            print(
                "   Evidencias: "
                + ", ".join(map(str, referencias))
            )

        print()


# ==================================================
# 2. MOSTRAR HERRAMIENTAS EJECUTADAS
# ==================================================

def mostrar_herramientas(evidencias):

    print("\n========== HERRAMIENTAS EJECUTADAS ==========\n")

    if not evidencias:
        print("No se registraron herramientas ejecutadas.")
        return

    for evidencia in evidencias:

        if not isinstance(evidencia, dict):
            continue

        referencia = evidencia.get("id", "sin_id")

        herramienta = evidencia.get(
            "herramienta", "desconocida"
        )

        estado = evidencia.get(
            "estado", "desconocido"
        )

        print(f"\n[{referencia}] {herramienta.upper()}")
        print(f"Estado: {estado}")

        if evidencia.get("ejecutor"):
            print(f"Ejecutor: {evidencia['ejecutor']}")

        if evidencia.get("origen_decision"):
            print(
                "Origen de la decisión: "
                f"{evidencia['origen_decision']}"
            )

        if evidencia.get("motivo"):
            print(f"Motivo: {evidencia['motivo']}")

        # ======================================
        # ERRORES
        # ======================================

        if estado == "error":

            if evidencia.get("tipo_error"):
                print(
                    f"Tipo de error: "
                    f"{evidencia['tipo_error']}"
                )

            print(
                "Detalle: "
                f"{evidencia.get('error', 'Sin detalle')}"
            )

            continue

        if estado == "sin_datos":

            print(
                "La herramienta no encontró información."
            )
            continue

        resultado = evidencia.get("resultado", {})

        if not isinstance(resultado, dict):
            continue

        # ======================================
        # NMAP
        # ======================================

        if herramienta == "nmap":

            print(
                "Alcance:",
                resultado.get(
                    "alcance", "No especificado"
                )
            )

            hosts = resultado.get("hosts", [])

            if not hosts:
                print("Sin hosts reportados.")

            for host in hosts:

                direcciones = (
                    host.get("direcciones") or []
                )

                print(
                    "IP: "
                    + (
                        ", ".join(map(str, direcciones))
                        or "No reportada"
                    )
                )

                for puerto in host.get("puertos", []):

                    print(
                        f"  {puerto.get('puerto')}/"
                        f"{puerto.get('protocolo')} "
                        f"{puerto.get('estado')} | "
                        f"{puerto.get('servicio') or 'no identificado'}"
                    )

                    if puerto.get("estado") == "open":

                        producto = " ".join(
                            filter(
                                None,
                                (
                                    puerto.get("producto"),
                                    puerto.get("version")
                                )
                            )
                        )

                        print(
                            "    Producto/versión: "
                            f"{producto or 'No determinados'}"
                        )

                        print(
                            "    Método: "
                            f"{puerto.get('metodo_identificacion') or 'No indicado'}"
                        )

        # ======================================
        # HTTP - LOGIN Y RAÍZ
        # ======================================

        elif herramienta in (
            "http_headers",
            "http_raiz"
        ):

            print(
                "Respuesta HTTP:",
                resultado.get(
                    "estado_http",
                    "No reportada"
                )
            )

            cabeceras = resultado.get(
                "cabeceras", {}
            )

            relevantes = (
                "server",
                "content-type",
                "location",
                "strict-transport-security",
                "content-security-policy",
                "x-frame-options",
                "x-content-type-options",
                "referrer-policy",
                "permissions-policy",
            )

            for nombre in relevantes:

                for valor in cabeceras.get(nombre, []):

                    print(f"  {nombre}: {valor}")

            cookies = resultado.get(
                "cookies_sin_valores", []
            )

            for cookie in cookies:

                nombre = cookie.get(
                    "nombre", "desconocida"
                )

                atributos = (
                    ", ".join(
                        cookie.get("atributos", [])
                    ) or "ninguno"
                )

                print(
                    f"  Cookie: {nombre} | "
                    f"atributos: {atributos}"
                )

        # ======================================
        # WHATWEB
        # ======================================

        elif herramienta == "whatweb":

            print("\nTecnologías identificadas:")

            print(
                resultado.get("identificacion")
                or "Sin identificación"
            )

        # ======================================
        # DNS
        # ======================================

        elif herramienta == "dns":

            registros = resultado.get(
                "registros", []
            )

            for registro in registros:
                print(f"  {registro}")

            if not registros:
                print("No se encontraron registros DNS.")

        # ======================================
        # TLS
        # ======================================

        elif herramienta == "tls":

            print("\nCertificado TLS:")

            print(
                resultado.get("certificado")
                or "Sin datos"
            )

            print(
                "Alcance:",
                resultado.get(
                    "alcance", "No especificado"
                )
            )

        # ======================================
        # HTML ESTÁTICO - V7
        # ======================================

        elif herramienta == "html_formularios":

            print(
                "Formularios en HTML estático:",
                resultado.get(
                    "cantidad_formularios", 0
                )
            )

            formularios = resultado.get(
                "formularios", []
            )

            if not formularios:
                print(
                    "No se encontraron formularios "
                    "en el HTML inicial."
                )

            for numero, formulario in enumerate(
                formularios, 1
            ):

                print(f"  Formulario {numero}:")

                print(
                    "    Método:",
                    formulario.get(
                        "method", "Desconocido"
                    )
                )

                print(
                    "    Destino:",
                    formulario.get(
                        "action", "Desconocido"
                    )
                )

                print(
                    "    Campo password:",
                    formulario.get(
                        "contiene_password", False
                    )
                )

            print(
                "Alcance:",
                resultado.get(
                    "alcance", "No especificado"
                )
            )

        # ======================================
        # NUEVO V8 - PLAYWRIGHT
        # ======================================

        elif herramienta == "browser_dom":

            print(
                "Título:",
                resultado.get(
                    "titulo", "No reportado"
                )
            )

            print(
                "URL final:",
                resultado.get(
                    "url_final", "No reportada"
                )
            )

            print(
                "Código de navegación:",
                resultado.get(
                    "estado_navegacion",
                    "No reportado"
                )
            )

            print(
                "Formularios renderizados:",
                resultado.get(
                    "cantidad_formularios", 0
                )
            )

            print(
                "Campos input:",
                resultado.get(
                    "cantidad_inputs", 0
                )
            )

            print(
                "Campos password:",
                resultado.get(
                    "campos_password", 0
                )
            )

            print(
                "Password fuera de form:",
                resultado.get(
                    "passwords_fuera_de_form", 0
                )
            )

            print(
                "Tipos de inputs:",
                ", ".join(
                    resultado.get(
                        "tipos_inputs", []
                    )
                ) or "Ninguno"
            )

            formularios = resultado.get(
                "formularios", []
            )

            for numero, formulario in enumerate(
                formularios, 1
            ):

                print(
                    f"\n  Formulario renderizado {numero}:"
                )

                print(
                    "    Método:",
                    formulario.get(
                        "method", "Desconocido"
                    )
                )

                print(
                    "    Destino:",
                    formulario.get(
                        "action", "Desconocido"
                    )
                )

                print(
                    "    Campo password:",
                    formulario.get(
                        "contiene_password", False
                    )
                )

            print(
                "\nAlcance:",
                resultado.get(
                    "alcance", "No especificado"
                )
            )

        # ======================================
        # NUEVO V8 - PROYECTO LOCAL
        # ======================================

        elif herramienta == "proyecto_local":

            manifestos = resultado.get(
                "manifestos", []
            )

            configuraciones = resultado.get(
                "configuraciones_nginx", []
            )

            print(
                "Manifiestos encontrados:",
                len(manifestos)
            )

            for archivo in manifestos:

                print(
                    f"\n  Archivo: {archivo.get('archivo')}"
                )

                if archivo.get("error"):

                    print(
                        f"  Error: {archivo['error']}"
                    )

                    continue

                print(
                    "  Tipo:",
                    archivo.get(
                        "tipo", "Desconocido"
                    )
                )

                dependencias = archivo.get(
                    "dependencias_declaradas", []
                )

                print(
                    "  Dependencias declaradas:",
                    len(dependencias)
                )

                for dependencia in dependencias[:12]:

                    if isinstance(dependencia, dict):

                        print(
                            "    "
                            f"{dependencia.get('nombre', '?')} "
                            f"{dependencia.get('version_declarada', '')}"
                        )

                    else:

                        print(f"    {dependencia}")

                if len(dependencias) > 12:

                    print(
                        f"    ... y "
                        f"{len(dependencias) - 12} más"
                    )

            print(
                "\nArchivos nginx revisados:",
                len(configuraciones)
            )

            for configuracion in configuraciones:

                print(
                    "\n  Archivo:",
                    configuracion.get("archivo")
                )

                print(
                    "  SSL declarado:",
                    configuracion.get(
                        "listen_ssl_declarado"
                    )
                )

                print(
                    "  Redirección HTTPS declarada:",
                    configuracion.get(
                        "redireccion_https_declarada"
                    )
                )

                print(
                    "  limit_req declarado:",
                    configuracion.get(
                        "limit_req_declarado"
                    )
                )

            print(
                "\nAlcance:",
                resultado.get(
                    "alcance", "No especificado"
                )
            )

        # ======================================
        # NUEVO V8 - AUDITORÍA DEPENDENCIAS
        # ======================================

        elif herramienta == "auditoria_dependencias":

            consultas = resultado.get(
                "consultas", []
            )

            print(
                "Consultas realizadas:",
                len(consultas)
            )

            for consulta in consultas:

                print(
                    "\n  Manifiesto:",
                    consulta.get("manifesto")
                )

                print(
                    "  Tipo:",
                    consulta.get(
                        "tipo", "No indicado"
                    )
                )

                print(
                    "  Estado:",
                    consulta.get("estado")
                )

                if consulta.get("detalle"):

                    print(
                        "  Detalle:",
                        consulta["detalle"]
                    )

                avisos = consulta.get(
                    "avisos", []
                )

                print(
                    "  Avisos:",
                    len(avisos)
                )

                for aviso in avisos[:15]:
                    print(f"    {aviso}")

            print(
                "\nAlcance:",
                resultado.get(
                    "alcance", "No especificado"
                )
            )

        else:

            print(
                "Resultado:",
                str(resultado)[:600]
            )


# ==================================================
# 3. MOSTRAR DECISIONES DE GEMINI
# ==================================================

def mostrar_decisiones(decisiones):

    print(
        "\n========== DECISIONES DEL AGENTE GEMINI ==========\n"
    )

    if not decisiones:
        print(
            "No se registraron decisiones adicionales."
        )
        return

    for numero, decision in enumerate(
        decisiones, 1
    ):

        print(
            f"{numero}. Ronda "
            f"{decision.get('ronda', numero)}"
        )

        print(
            "   Acción:",
            decision.get(
                "accion", "desconocida"
            )
        )

        print(
            "   Origen:",
            decision.get(
                "origen_decision", "No indicado"
            )
        )

        original = decision.get(
            "accion_original_ia"
        )

        if (
            original
            and original != decision.get("accion")
        ):

            print(
                "   Propuesta original de Gemini:",
                original
            )

        if decision.get("motivo"):
            print(
                f"   Motivo: {decision['motivo']}"
            )

        if decision.get("hipotesis"):
            print(
                f"   Hipótesis: {decision['hipotesis']}"
            )

        if decision.get("criterio"):
            print(
                f"   Criterio: {decision['criterio']}"
            )

        if decision.get("evidencia_generada"):
            print(
                "   Evidencia:",
                decision["evidencia_generada"]
            )

        if decision.get("estado"):
            print(
                f"   Resultado: {decision['estado']}"
            )

        print()


# ==================================================
# 4. MOSTRAR COBERTURA
# ==================================================

def mostrar_cobertura(cobertura):

    print(
        "\n========== COBERTURA DEL ANÁLISIS ==========\n"
    )

    print(
        "Modo:",
        cobertura.get(
            "modo", "No especificado"
        )
    )

    for clave, etiqueta in (
        ("herramientas_ok", "Herramientas correctas"),
        ("herramientas_error", "Herramientas con errores"),
        ("herramientas_sin_datos", "Herramientas sin datos"),
    ):

        print(
            etiqueta + ":",
            ", ".join(
                cobertura.get(clave, [])
            ) or "Ninguna"
        )

    print(
        "Observaciones OSINT:",
        cobertura.get(
            "observaciones_osint", 0
        )
    )

    print(
        "Observaciones técnicas:",
        cobertura.get(
            "observaciones_tecnicas",
            cobertura.get(
                "observaciones", 0
            )
        )
    )

    print(
        "Configuraciones verificadas:",
        cobertura.get(
            "hallazgos_verificados", 0
        )
    )


# ==================================================
# 5. NUEVO V8 - CALIDAD DEL INFORME
# ==================================================

def mostrar_calidad(calidad):

    print(
        "\n========== CALIDAD Y LIMITACIONES DEL INFORME ==========\n"
    )

    if not calidad:

        print(
            "Sin indicadores adicionales."
        )

        return

    print(
        "Inventario completo:",
        calidad.get(
            "inventario_completo", False
        )
    )

    print(
        "Puertos examinados:",
        calidad.get(
            "puertos_examinados",
            "No especificados"
        )
    )

    print(
        "Hipótesis sin resolver:",
        calidad.get(
            "hipotesis_sin_resolver",
            "No informado"
        )
    )

    print(
        "Playwright correcto:",
        calidad.get(
            "browser_dom_correcto", False
        )
    )

    print(
        "Proyecto local revisado:",
        calidad.get(
            "proyecto_local_revisado", False
        )
    )

    print(
        "\nNota: los banners y los avisos "
        "de dependencias no confirman por "
        "sí solos vulnerabilidades en producción."
    )


# ==================================================
# 6. NUEVO V8 - AVISOS DE DEPENDENCIAS
# ==================================================

def mostrar_avisos(avisos):

    print(
        "\n========== AVISOS DE DEPENDENCIAS LOCALES ==========\n"
    )

    if not avisos:

        print(
            "No hay avisos registrados o "
            "no se ejecutó una auditoría local."
        )

        return

    for numero, aviso in enumerate(
        avisos, 1
    ):

        print(
            f"{numero}. Manifiesto: "
            f"{aviso.get('manifesto', 'No indicado')}"
        )

        print(
            "   Paquete:",
            aviso.get(
                "paquete", "No indicado"
            )
        )

        if aviso.get("version"):

            print(
                f"   Versión: {aviso['version']}"
            )

        if aviso.get("severidad"):

            print(
                "   Severidad informada:",
                aviso["severidad"]
            )

        if aviso.get("avisos"):

            print(
                "   Referencias:",
                ", ".join(
                    map(str, aviso["avisos"])
                )
            )

        print()


# ==================================================
# 7. MOSTRAR INFORME FINAL
# ==================================================

def mostrar_informe(resultado):

    version = resultado.get(
        "version_agente", "desconocida"
    )

    print("\n=================================")
    print(f"       INFORME FINAL V{version}")
    print("=================================\n")

    print(
        "Objetivo:",
        resultado.get(
            "objetivo", "No indicado"
        )
    )

    print(
        "Modelo:",
        resultado.get(
            "modelo", "No indicado"
        )
    )

    print(
        "\n========== RESUMEN EJECUTIVO ==========\n"
    )

    print(
        resultado.get("resumen")
        or "No se generó resumen."
    )

    secciones = (
        (
            "HECHOS OSINT CON EVIDENCIA",
            "observaciones_osint"
        ),
        (
            "OBSERVACIONES TÉCNICAS",
            "observaciones_verificadas"
        ),
        (
            "CONFIGURACIONES DE SEGURIDAD VERIFICADAS",
            "hallazgos"
        ),
        (
            "VULNERABILIDADES CONFIRMADAS",
            "vulnerabilidades_confirmadas"
        ),
        (
            "HIPÓTESIS DE SEGURIDAD",
            "hipotesis"
        ),
        (
            "CORRELACIONES DE EVIDENCIAS",
            "correlaciones"
        ),
        (
            "RIESGOS DE DISPONIBILIDAD POR VALIDAR",
            "riesgos_disponibilidad"
        ),
        (
            "INFORMACIÓN PENDIENTE",
            "pendientes"
        ),
        (
            "RECOMENDACIONES DEFENSIVAS",
            "recomendaciones"
        ),
        (
            "CONTROLES DE SEGURIDAD OBSERVADOS",
            "controles_observados"
        ),
        (
            "CONTRADICCIONES POR REVISAR",
            "contradicciones"
        ),
    )

    for titulo, clave in secciones:

        mostrar_seccion(
            titulo,
            resultado.get(clave, [])
        )

    # ======================================
    # AVISOS DE DEPENDENCIAS
    # ======================================

    mostrar_avisos(
        resultado.get(
            "avisos_dependencias", []
        )
    )

    # ======================================
    # HERRAMIENTAS
    # ======================================

    mostrar_herramientas(
        resultado.get(
            "evidencias_tecnicas", []
        )
    )

    # ======================================
    # DECISIONES AUTÓNOMAS
    # ======================================

    mostrar_decisiones(
        resultado.get(
            "decisiones_agente", []
        )
    )

    # ======================================
    # COBERTURA
    # ======================================

    mostrar_cobertura(
        resultado.get(
            "cobertura", {}
        )
    )

    # ======================================
    # CALIDAD
    # ======================================

    mostrar_calidad(
        resultado.get(
            "calidad_informe", {}
        )
    )

    print("\n=================================")
    print("       ANÁLISIS FINALIZADO")
    print("=================================\n")


# ==================================================
# 8. FUNCIÓN PRINCIPAL
# ==================================================

def main():

    print("\n=================================")
    print("       AI RECON AGENT")
    print("=================================")

    kali = KaliSSHClient()
    policy = ScopePolicy.from_environment()

    agente_osint = None

    try:

        # ======================================
        # CONEXIÓN CON KALI
        # ======================================

        kali.conectar()

        # ======================================
        # INICIALIZACIÓN DE AGENTES
        # ======================================

        agente_osint = AgenteOSINT(kali, policy=policy)

        agente_reconocimiento = (
            AgenteReconocimiento(kali, policy=policy)
        )

        # ======================================
        # INTERACCIÓN CON EL USUARIO
        # ======================================

        while True:

            print("\n---------------------------------")

            try:

                objetivo = input(
                    "Introduce una URL, dominio o IP "
                    "(o 'salir'): "
                ).strip()

            except (KeyboardInterrupt, EOFError):

                print(
                    "\n[MAIN] Entrada interrumpida."
                )

                break

            if objetivo.lower() == "salir":
                break

            if not objetivo:

                print(
                    "Introduce un objetivo válido."
                )

                continue

            try:

                # ==================================
                # AGENTE 1: GROQ + QWEN
                # ==================================

                print(
                    "\n========== AGENTE OSINT ==========\n"
                )

                resultado_osint = (
                    agente_osint.investigar(
                        objetivo
                    )
                )

                if not isinstance(
                    resultado_osint, dict
                ):

                    raise TypeError(
                        "El agente OSINT no devolvió "
                        "un diccionario válido."
                    )

                print(
                    "\n========== OSINT FINALIZADO ==========\n"
                )

                print(
                    "Objetivo:",
                    resultado_osint.get("objetivo")
                )

                print(
                    "Estado:",
                    resultado_osint.get("estado")
                )

                print(
                    "Modelo:",
                    resultado_osint.get("modelo")
                )

                print(
                    "Evidencias:",
                    len(
                        resultado_osint.get(
                            "evidencias", []
                        )
                    )
                )

                print(
                    "Hechos:",
                    len(
                        resultado_osint.get(
                            "hechos", []
                        )
                    )
                )

                # ==================================
                # AGENTE 2: GEMINI + KALI + PLAYWRIGHT
                # ==================================

                print(
                    "\n========== AGENTE RECONOCIMIENTO ==========\n"
                )

                resultado_final = (
                    agente_reconocimiento.analizar(
                        resultado_osint
                    )
                )

                if not isinstance(
                    resultado_final, dict
                ):

                    raise TypeError(
                        "El agente de reconocimiento "
                        "no devolvió un diccionario válido."
                    )

                # ==================================
                # INFORME FINAL
                # ==================================

                mostrar_informe(resultado_final)

                # Los dos resultados permanecen
                # disponibles en memoria:
                #
                # resultado_osint
                # resultado_final
                #
                # La persistencia del agente OSINT
                # se administra por separado.

                print(
                    "[MAIN] Reconocimiento completado."
                )

            except Exception as error:

                print(
                    f"\n[ERROR] "
                    f"{type(error).__name__}: {error}"
                )

    finally:

        # ======================================
        # CERRAR CONEXIONES
        # ======================================

        try:

            if agente_osint is not None:
                agente_osint.cerrar()

        finally:

            kali.cerrar()

        print("\nPrograma finalizado.")


if __name__ == "__main__":
    main()
