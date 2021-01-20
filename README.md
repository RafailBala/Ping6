
# Использование интерфейса низкоуровневого доступа к сетевому программированию ("сырые" сокеты) через механизм выполнения нативного кода из Java (JNI).

Задача: необходимо отослать ping запрос на MAC-адрес и IP-адрес сервера, принять ответ, и вывести ответный буфер на экран.

План реализации:
  - Создание класс решения прикладной задачи на Java с использованием нативных (native) функций
  - Генерация заголовочного файла на C, на основе реализованного класса в Java
  - Реализация функций из заголовочного файла на языке С
  - Компиляция динамической библиотеки для последующего использования в JVM
  - Проверка работы Java приложения

### Компиляция динамической библиотеки для последующего использования в JVM

Для компиляции динамической библиотеки используется компилятор GCC со
следующими флагами:
-fPIC - Position Independent Code;
-shared - динамическая библиотека;
-o libИмяБиблиотеки.so - выходной файл;
-I. - поиск заголовочных файлов в текущей дериктории.
      Для подключания заголовочного файла библиотеки.
-I/path/to/jdk/include - поиск заголовочного файла jni.h;
-I/path/to/jdk/include/linux - поиск заголовочного файла jni_md.h;

      Пример для Linux:
      -I/usr/lib/jvm/java-8-openjdk/include
      -I/usr/lib/jvm/java-8-openjdk/include/linux

Общая команда компиляции динамической библиотеки:
```sh
$ gcc -fPIC -shared -I. -I/path/to/jdk/include -o libИмяБиблиотеки.so *.c
```
### Проверка работы Java приложения
Запуск приложения осуществлять с установленным параметром java.library.path.
В терминале:
```sh
$ java -Djava.library.path=. RunJavaClass
```

### Пример компиляции и запуска
    
1. Необходимо создать заголовочный файл:

Если у вас установлено JDK-8, то
```sh
$ javac  Main.java
```
Если у вас установлено JDK-11, то
```sh
$ javac -h . Main.java
```
2. Необходимо создать файл библиотеки:
```sh
$ sudo gcc -fPIC -shared -I. -I/usr/lib/jvm/java-11-openjdk-amd64/include -I/usr/lib/jvm/java-11-openjdk-amd64/include/linux -o libLabNat.so Ping6.c
```
Есть небольшая вероятность, что Вам придется указать иные директории для поиска заголовочных фалов jni.h и jni_md.h.
3. Запуск приложения

```sh
$ sudo java -Djava.library.path=/home/user/Ping6 Main
```
Не забудьте изменить директорию!

