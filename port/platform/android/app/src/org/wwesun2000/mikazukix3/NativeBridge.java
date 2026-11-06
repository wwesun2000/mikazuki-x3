package org.wwesun2000.mikazukix3;

final class NativeBridge {
    static { System.loadLibrary("mikazuki"); }
    static native byte[] open(int fd,String root);
    static native void start(String edition,int slot);
    static native int[] notes(String edition);
    static native void action(int kind,int index);
    static native void tick(int held);
    static native byte[] state();
    static native void language(int language);
    static native void pause(boolean paused,boolean checkpoint);
    static native void save(int slot);
    static native void home();
    static native void retry();
    static native void render(android.graphics.Bitmap scene,android.graphics.Bitmap layer,android.graphics.Bitmap foreground,boolean scan);
}
