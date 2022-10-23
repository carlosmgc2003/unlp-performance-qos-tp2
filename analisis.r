bytesperconn <- read.csv("datos_provistos/bytesperconn.dat",header = FALSE)
#print(typeof(bytesperconn))
#print(typeof(bytesperconn$V1))
#hist(bytesperconn$V1)
pktsperconn <- read.csv("datos_provistos/pktsperconn.dat", header = FALSE)
#print(pktsperconn)
#hist(pktsperconn$V1)
timeperconn <- read.csv("datos_provistos/timeperconn.dat", header = FALSE)
datos <- data.frame(unlist(bytesperconn, use.names = FALSE),
                    unlist(pktsperconn, use.name = FALSE),
                    unlist(timeperconn, use.name = FALSE))
names(datos) <- c("bytesperconn", "pktsperconn", "timeperconn")

# Punto 2 - Trace un histograma de frecuencia para mostrar la 
# distribución de la duración de las
# conexiones TCP exitosas observadas.
print("Tiempo por conexión")
print(summary(datos$timeperconn))
hist(datos$timeperconn,
        xlab = "Tiempo por conexión",
        ylab = "Frecuencia",
        main = "Histograma de frecuencias  de duración de las conexiones TCP exitosas", # nolint
        breaks = seq(0, 1660, 20),
        xaxp = c(0, 1660, 83),
        xlim = c(0, 1660),
        col = rainbow(1))
abline(h = seq(0, 350, 50),
        col = "gray",
        lty = "dotted")

# Punto 3 - Trace un histograma de frecuencia para mostrar ola distribución
# de paquetes por conexion TCP.
print("Paquetes por conexion")
print(summary(datos$pktsperconn))
hist(datos$pktsperconn,
        xlab = "Paquetes por conexión",
        ylab = "Frecuencia",
        main = "Histograma de frecuencias  de paquetes de las conexiones TCP exitosas", # nolint
        breaks = seq(0, 462,42),
        xaxp = c(0, 462, 11),
        xlim = c(0, 461),
        ylim = c(0, 350),
        col = rainbow(1)
        )
abline(h = seq(0, 350, 50),
        col = "gray",
        lty = "dotted")

# Punto 4 - Trace un histograma de frecuencia para mostrar ola distribución
# de bytes por conexion TCP.
print("bytes por conexion")
print(summary(datos$bytesperconn))
hist(datos$bytesperconn,
        xlab = "Bytes por conexión",
        ylab = "Frecuencia",
        main = "Histograma de frecuencias de bytes de las conexiones TCP exitosas", # nolint
        breaks = seq(0, 388000, 4000),
        xaxp = c(0, 388000, 97),
        xlim = c(0, 376000),
        yaxp = c(0, 250, 10),
        ylim = c(0, 250),
        col = rainbow(1)
        )
abline(h = seq(0, 250, 25),
        col = "gray",
        lty = "dotted")
