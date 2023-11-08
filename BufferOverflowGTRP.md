# Ejemplos de Buffer Overflow

## 1. CVE-2022-3349 en Sony PS4 y PS5

### Descripción
Se descubrió una vulnerabilidad crítica en las consolas Sony PS4 y PS5 que afecta a la función `UVFAT_readupcasetable` dentro del controlador exFAT. La manipulación inapropiada del argumento `dataLength` puede provocar un desbordamiento de buffer basado en heap.

### Cómo Derivó en Fallas de Seguridad
Esta vulnerabilidad se debe a un error en la conversión de una variable de tamaño de entero de 64 bits a 32 bits dentro de la implementación del sistema de archivos exFAT de Sony. Este error conduce a una asignación incorrecta de memoria para la tabla de mayúsculas, lo que, con un valor manipulado de `dataLength`, puede resultar en un desbordamiento de buffer. Este overflow puede sobrescribir objetos adyacentes en el heap, lo que podría ser explotado para ejecutar código arbitrario y potencialmente permitir un jailbreak de la consola.

### Referencia del Código
El reporte completo de la vulnerabilidad está disponible en HackerOne:
[Reporte de Vulnerabilidad CVE-2022-3349](https://hackerone.com/reports/1340942)

### Fragmento del Código
```c
int UVFAT_readupcasetable(void *unused, void *fileSystem) {
  ...
  size_t dataLength = *(size_t *)(upcaseEntry + 24);
  size_t size = sectorSize + dataLength - 1;
  size = size - size % sectorSize;
  uint8_t *data = sceFatfsCreateHeapVl(0, size);
  ...
  while (1) {
    ...
    UVFAT_ReadDevice(fileSystem, offset, sectorSize, data);
    ...
    data += sectorSize;
    ...
  }
}

void *sceFatfsCreateHeapVl(void *unused, int size) {
  return malloc(size, M_EXFATFSPATH, M_WAITOK | M_ZERO);
}
```
Cuando se utiliza un valor grande para dataLength, la función sceFatfsCreateHeapVl() solo asignará un buffer pequeño, y como resultado se producirá un desbordamiento y corrupción de objetos subsecuentes en el montículo al llamar a UVFAT_ReadDevice(). Por ejemplo, usando sectorSize=0x200 y dataLength=0x100000200 obtenemos que size será 0x200 después de la truncación, lo que resulta en un desbordamiento cuando el tamaño real debía ser 0x100000200.

## 2. CVE-2023-40164 en Notepad++

### Descripción
Se descubrió un desbordamiento de buffer de lectura basado en heap en la función `FileManager::detectLanguageFromTextBegining` de Notepad++. Al abrir un archivo, Notepad++ llama a `FileManager::loadFile`, donde se asigna un buffer de tamaño fijo. Sin embargo, la función `FileManager::detectLanguageFromTextBegining` puede leer más allá del final del buffer asignado.

### Cómo Derivó en Fallas de Seguridad
Durante la detección del tipo de contenido al principio del archivo, si se alcanza el valor de `lenFile`, el código continúa leyendo 32 bytes más allá del final del buffer de datos. No hay una verificación adecuada para garantizar que `i + longestLength` sea menor que `dataLen`, lo que podría resultar en una lectura fuera de los límites (OOB READ). Podría usarse para filtrar información sobre la asignación interna de memoria.

### Referencia del Código
El aviso de seguridad completo se encuentra en el GitHub Security Lab:
[GHSL-2023-092_Notepad++](https://securitylab.github.com/advisories/GHSL-2023-092_Notepad__/)

### Fragmento del Código
```c++
char* data = new char[blockSize + 8]; // +8 for incomplete multibyte char
...
bool res = loadFileData(doc, fileSize, backupFileName ? backupFileName : fullpath, data, &UnicodeConvertor, loadedFileFormat);
delete[] data;

...

LangType FileManager::detectLanguageFromTextBegining(const unsigned char *data, size_t dataLen)
{
    ...
    // Skip any space-like char
    for (; i < dataLen; ++i) // 3
    {
        if (data[i] != ' ' && data[i] != '\t' && data[i] != '\n' && data[i] != '\r')
            break;
    }

    // Create the buffer to need to test
    const size_t longestLength = 40; // shebangs can be large
    std::string buf2Test = std::string((const char*)data + i, longestLength); // 4 OOB READ
    ...
}
```
En este código, el bucle finaliza sin verificar si la suma de i + longestLength excede dataLen, lo que podría causar que el contenido de la memoria después del buffer se incorpore en buf2Test.

## 3. CVE-2023-25664 en TensorFlow

### Descripción
En la plataforma de aprendizaje automático de código abierto TensorFlow, se identificó una vulnerabilidad de desbordamiento de buffer en el heap en `TAvgPoolGrad`. Las versiones afectadas son anteriores a TensorFlow 2.12.0 y 2.11.1.

### Cómo Derivó en Fallas de Seguridad
La vulnerabilidad es consecuencia de un desbordamiento de buffer en la operación de gradiente para el promedio de agrupamiento (`AvgPoolGrad`). Los tamaños incorrectamente calculados o verificados para las operaciones de agrupamiento pueden conducir a que se escriba más allá del final del buffer de heap asignado durante el cálculo del gradiente, potencialmente permitiendo la ejecución de código arbitrario o causando una denegación de servicio (DoS).

### Referencia del Código
El aviso de seguridad está disponible en el repositorio de GitHub de TensorFlow:
[CVE-2023-25664 TensorFlow Advisory](https://github.com/tensorflow/tensorflow/security/advisories/GHSA-6hg6-5c2q-7rcr)

### Fragmento del Código
```python
import os
os.environ['TF_ENABLE_ONEDNN_OPTS'] = '0'
import tensorflow as tf
print(tf.__version__)
with tf.device("CPU"):
    ksize = [1, 40, 128, 1]
    strides = [1, 128, 128, 30]
    padding = "SAME"
    data_format = "NHWC"
    orig_input_shape = [11, 9, 78, 9]
    grad = tf.saturate_cast(tf.random.uniform([16, 16, 16, 16], minval=-128, maxval=129, dtype=tf.int64), dtype=tf.float32)
    res = tf.raw_ops.AvgPoolGrad(
        ksize=ksize,
        strides=strides,
        padding=padding,
        data_format=data_format,
        orig_input_shape=orig_input_shape,
        grad=grad,
    )
```
En este código, el problema reside en cómo se calculan los tamaños de `ksize`, `strides`, y `orig_input_shape`, lo cual podría resultar en que la función `AvgPoolGrad` escriba fuera de los límites del buffer asignado en el heap.

## 4. CVE-2022-30067 en GIMP

### Descripción
GIMP (GNU Image Manipulation Program) versiones 2.10.30 y 2.99.10 contienen una vulnerabilidad de desbordamiento de buffer al procesar archivos XCF manipulados. El programa intenta asignar una cantidad excesivamente grande de memoria cuando se abre un archivo XCF malicioso, lo que puede resultar en la falta de memoria o el cierre inesperado del programa.

### Cómo Derivó en Fallas de Seguridad
La vulnerabilidad ocurre debido a que no hay una comprobación adecuada del tamaño del búfer al cargar rutas antiguas desde archivos XCF. Cuando se procesa un número excesivamente alto de puntos de ruta (`num_points`), el programa intenta asignar una cantidad de memoria basada en este número sin verificar primero si la asignación es demasiado grande, lo que lleva a un posible desbordamiento de búfer en el heap o un error de asignación de memoria.

### Referencia del Código
El informe de error y la discusión sobre la corrección del mismo están disponibles en el GitLab oficial de GNOME/GIMP:
[Issue #8120 - GIMP 2.10.30 crashed when allocate large memory](https://gitlab.gnome.org/GNOME/gimp/-/issues/8120)

### Fragmento del Código
El fragmento de código relevante se encuentra en el archivo `xcf-load.c` del código fuente de GIMP, donde la función `xcf_load_old_paths` lee un entero de 32 bits del archivo XCF para `num_points` y luego intenta asignar memoria basada en este valor sin una comprobación adecuada:

```c
// gimp-2.10.30/app/xcf/xcf-load.c:2755
xcf_read_int32(info, &num_points, 1);
...
// gimp-2.10.30/app/xcf/xcf-load.c:2780
if (num_points == 0) {
  g_free(name);
  return FALSE;
}

points = g_new0(GimpVectorsCompatPoint, num_points);
```

Si `num_points` es muy grande (como se muestra en el depurador con un valor de `0x72696400` que es aproximadamente 1919 millones), la llamada a `g_new0` intentará asignar una cantidad de memoria que es probablemente más de lo que el sistema puede manejar, lo que lleva a un fallo de asignación y posiblemente a una corrupción de memoria si el programa no maneja correctamente este error.

## 4. CVE-2021-31323 en Telegram (rlottie)

### Descripción
Las versiones de Telegram anteriores a la 7.1.0 para Android, antes de la 7.1 para iOS y antes de la 7.1 para macOS tienen una vulnerabilidad de desbordamiento de buffer en el heap en la función `LottieParserImpl::parseDashProperty` de su fork personalizado de la biblioteca rlottie. 

### Cómo Derivó en Fallas de Seguridad
Este desbordamiento ocurre porque la aplicación no verifica el número real de guiones en la pegatina animada antes de acceder a la memoria del heap. Si una pegatina contiene más guiones de los esperados, la función accede a memoria fuera de los límites asignados. Un atacante remoto podría explotar esta vulnerabilidad para acceder a la memoria del heap fuera de sus límites en un dispositivo víctima a través de una pegatina animada maliciosa.

### Referencia del Código
La vulnerabilidad y el análisis técnico están disponibles en Shielder:
[Advisory by Shielder on Telegram rlottie Heap Buffer Overflow](https://www.shielder.com/advisories/telegram-rlottie-lottieparserimpl-parsedashproperty-heap-buffer-overflow/)

### Fragmento del Código
El código fuente que contiene la vulnerabilidad está en el repositorio de Telegram en GitHub:
```cpp
void LottieParserImpl::parseDashProperty(LOTDashProperty &dash) {
    dash.mDashCount = 0;
    dash.mStatic = true;
    ...
    while (NextArrayValue()) {
        ...
        while (const char *key = NextObjectKey()) {
            if (0 == strcmp(key, "v")) {
                parseProperty(dash.mDashArray[dash.mDashCount++]);
            }
            ...
        }
        ...
    }
    ...
    for (int i = 0; i < dash.mDashCount; i++) {
        if (!dash.mDashArray[i].isStatic()) {
            dash.mStatic = false;
            break;
        }
    }
}
```
[Código Fuente en GitHub](https://github.com/DrKLO/Telegram/blob/release-7.0.1_2065/TMessagesProj/jni/rlottie/src/lottie/lottieparser.cpp#L1866)

La estructura `LOTDashProperty` solo puede contener un número fijo de guiones, pero si se presentan más, se accede a memoria fuera de los límites, lo que puede llevar a lecturas fuera de los límites y potencialmente a la ejecución de código arbitrario.
