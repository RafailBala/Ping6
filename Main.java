class LabNat {
    public static native boolean init(String interfaceName);//инициализирует работу с "сырыми" сокетами.
    public static native void deinit();//завершает работу с сырыми сокетами, возвращает используюмую память системе.
    public static native int sendTo(byte[] buf);//отсылает через сырые сокеты буфер buf. Возвращает количество посланных байт, или -1 при ошибке.
    public static native byte[] recvFrom(byte[] buf, int offset);//прием первого пакета, содержимое которого совпадает с buf со смещения offset. Возвращает массив присланных байт.
    static{
        System.loadLibrary("LabNat");
    }
}

public class Main {

    public static void main(String[] args)
    {
        boolean f = LabNat.init("enp0s3");
        System.out.print("Инициализаяция: " );
        System.out.println(f);
        int i = LabNat.sendTo(new byte[]{0x11,0x12,0x13,0x1a,0x1b,0x1c});
        System.out.print("Число переданных байт: ");
        System.out.println(i);
        byte [] mas = LabNat.recvFrom(new byte[]{0x11,0x12,0x13,0x1a,0x1b,0x1c},66);
        System.out.print("Массив принятых байт: ");
        for(int j=0;j < mas.length; j++)
        {
	   System.out.printf("%x",mas[j]);
        }
        System.out.println("");
        System.out.println("----------------------------------------------");
        LabNat.deinit();
    }
}
