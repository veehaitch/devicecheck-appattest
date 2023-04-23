package ch.veehait.devicecheck.appattest.common

import ch.veehait.devicecheck.appattest.util.Utils
import java.security.cert.X509Certificate

sealed class EqualsVerifierPrefabValues<T>(
    val red: T,
    val blue: T,
) {
    object HttpHeaders : EqualsVerifierPrefabValues<java.net.http.HttpHeaders>(
        red = java.net.http.HttpHeaders.of(mapOf("Content-Type" to listOf("red"))) { _, _ -> true },
        blue = java.net.http.HttpHeaders.of(mapOf("Content-Type" to listOf("blue"))) { _, _ -> true },
    )

    object X509Certificates : EqualsVerifierPrefabValues<X509Certificate>(
        red = Utils.readPemX509Certificate(
            """
                -----BEGIN CERTIFICATE-----
                MIIEqDCCA5CgAwIBAgISA1J1Te/uw+/K5zE/oUxjF5k1MA0GCSqGSIb3DQEBCwUA
                MEoxCzAJBgNVBAYTAlVTMRYwFAYDVQQKEw1MZXQncyBFbmNyeXB0MSMwIQYDVQQD
                ExpMZXQncyBFbmNyeXB0IEF1dGhvcml0eSBYMzAeFw0yMDA3MjIwMTQwNDlaFw0y
                MDEwMjAwMTQwNDlaMB0xGzAZBgNVBAMTEnZpbmNlbnQtaGF1cGVydC5kZTBZMBMG
                ByqGSM49AgEGCCqGSM49AwEHA0IABIK1fweRA2ElQHOiXj6mV1p2h9jqT9sbQndn
                am/KYi3QshqtMPzpNuAMvrGQ/SzlL5/7NPnCmpD/WVFeth/h+rajggJ+MIICejAO
                BgNVHQ8BAf8EBAMCB4AwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMAwG
                A1UdEwEB/wQCMAAwHQYDVR0OBBYEFOwUdPAtilNuXSyWMYXndWteex8nMB8GA1Ud
                IwQYMBaAFKhKamMEfd265tE5t6ZFZe/zqOyhMG8GCCsGAQUFBwEBBGMwYTAuBggr
                BgEFBQcwAYYiaHR0cDovL29jc3AuaW50LXgzLmxldHNlbmNyeXB0Lm9yZzAvBggr
                BgEFBQcwAoYjaHR0cDovL2NlcnQuaW50LXgzLmxldHNlbmNyeXB0Lm9yZy8wNQYD
                VR0RBC4wLIISdmluY2VudC1oYXVwZXJ0LmRlghZ3d3cudmluY2VudC1oYXVwZXJ0
                LmRlMEwGA1UdIARFMEMwCAYGZ4EMAQIBMDcGCysGAQQBgt8TAQEBMCgwJgYIKwYB
                BQUHAgEWGmh0dHA6Ly9jcHMubGV0c2VuY3J5cHQub3JnMIIBAwYKKwYBBAHWeQIE
                AgSB9ASB8QDvAHYA8JWkWfIA0YJAEC0vk4iOrUv+HUfjmeHQNKawqKqOsnMAAAFz
                dGUY+gAABAMARzBFAiEAqQk8W5u2Yc/8hoYu+rtsQlnKipsIhZ++4gEWdrfZrWoC
                ICDpmtsjP4FCLvJcI6NumaLFmRjI/Mhzkrl0ZTIhc6RuAHUAsh4FzIuizYogTodm
                +Su5iiUgZ2va+nDnsklTLe+LkF4AAAFzdGUY8gAABAMARjBEAiB1KJfW5an7Op9Y
                /QA2hvWuhTlmDTQMn32tDus41sm6ZgIgHQi9DXZzjZFdl6WMdYuIy4xcEC9KivfB
                93Qsr2MNHWAwDQYJKoZIhvcNAQELBQADggEBAAUPAAp7pxNxj/Tx/MZjvPriFwL6
                7dZXctCMqV/7JSA5ypGTDvRq8uJOnxBLLac0hIY2LyQZXVSKYZsqhn8p7nGRCf1T
                e8kx6WcCiqRuSt1vkBo5xzc98eFG+fdENPXhR8vLTkYpwtu8NU48sGeudumlC81u
                v498SMVuxVdut6DAO1zwKGi5NFBUwF9UknC5Lh6nyHhvz+VccDi1H6GNfvk8BGUO
                2AncM7gxi0kibrXZQHTeSzG0SYBhkXqS64/uDPv73K7FzRvevae9tv3OjX0sCsTm
                msRUBPdJ5wSyLDN51adVxNk+WeoXTYEyAnDZx2P3lreRahI4pahMZQ+qe0w=
                -----END CERTIFICATE-----
            """.trimIndent(),
        ),
        blue = Utils.readPemX509Certificate(
            """
                -----BEGIN CERTIFICATE-----
                MIIEkzCCA3ugAwIBAgISA+711xJ31t0DAluoWPd4x1ljMA0GCSqGSIb3DQEBCwUA
                MEoxCzAJBgNVBAYTAlVTMRYwFAYDVQQKEw1MZXQncyBFbmNyeXB0MSMwIQYDVQQD
                ExpMZXQncyBFbmNyeXB0IEF1dGhvcml0eSBYMzAeFw0yMDA4MjYwMTQwNDdaFw0y
                MDExMjQwMTQwNDdaMBUxEzARBgNVBAMTCnZlZWhhaXQuY2gwWTATBgcqhkjOPQIB
                BggqhkjOPQMBBwNCAASn+ThdLnZbVRPgLydEGoDiQRt82cVWIc4nGD/KMX050Fg0
                8PlqJl64EZHmrm+ZBojW9LRYENZVbsBMFZErv+fno4ICcTCCAm0wDgYDVR0PAQH/
                BAQDAgeAMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjAMBgNVHRMBAf8E
                AjAAMB0GA1UdDgQWBBREm+MwRWjmDMz5m9lbC9K9L/KDsjAfBgNVHSMEGDAWgBSo
                SmpjBH3duubRObemRWXv86jsoTBvBggrBgEFBQcBAQRjMGEwLgYIKwYBBQUHMAGG
                Imh0dHA6Ly9vY3NwLmludC14My5sZXRzZW5jcnlwdC5vcmcwLwYIKwYBBQUHMAKG
                I2h0dHA6Ly9jZXJ0LmludC14My5sZXRzZW5jcnlwdC5vcmcvMCUGA1UdEQQeMByC
                CnZlZWhhaXQuY2iCDnd3dy52ZWVoYWl0LmNoMEwGA1UdIARFMEMwCAYGZ4EMAQIB
                MDcGCysGAQQBgt8TAQEBMCgwJgYIKwYBBQUHAgEWGmh0dHA6Ly9jcHMubGV0c2Vu
                Y3J5cHQub3JnMIIBBgYKKwYBBAHWeQIEAgSB9wSB9ADyAHcAXqdz+d9WwOe1Nkh9
                0EngMnqRmgyEoRIShBh1loFxRVgAAAF0KKOkkQAABAMASDBGAiEA9pKTjbXoM9gK
                flivH7H9RdCu4vyHv3SPLOqwSW63i6YCIQC/kpc3HxcgbVAOp9zTROpaMo2smU9u
                IOGucW9siTE4ggB3AAe3XBvlfWj/8bDGHSMVx7rmV3xXlLdq7rxhOhpp06IcAAAB
                dCijpNQAAAQDAEgwRgIhAPy/RzfZd3wqXT9vxOW9NS3QntRD1TCmiRTnJ8w2xick
                AiEAigHG00MXZhiNrUWfEvRXLLSGCB+/uLCy8BpRGKio8N4wDQYJKoZIhvcNAQEL
                BQADggEBAEkYgANp+mp8gYQX1egKYJIASa8zuCaWMlOlE0iPzuqYjEBZLdVo2lQG
                n6ck1oBPUHq//zfIBvCsighm5mjtMa6LczjXPL8Qi2PId0Fy3DlnRv3vJz4PGiI+
                vz+cZVCs3FwSdZcy66GMbg74NLnNVXmbERGBy+VVED/yE+fhbKEAqXXAZ0oTqQVM
                DwrNAWmcog6OSGLMZPLI2P93IQYOu0SHXGuln4uY5/k0/dAD0r0+CLeBD3Oq8YrZ
                XTdkr8pvD5cuqziRk84Jl0v2Ac3lxf2HzKWf9hWDU1B9OwP8qq1D4LCiADOwCeh6
                6cknwJIB7bDU6Witj6sIKo4kuYld4+4=
                -----END CERTIFICATE-----
            """.trimIndent(),
        ),
    )
}
