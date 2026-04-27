package Y0;

import h2.C0563i;
import h2.p;
import i2.AbstractC0580h;
import i2.C;
import java.io.IOException;
import java.io.InputStream;
import java.util.Collection;
import java.util.Iterator;

/* JADX INFO: loaded from: classes.dex */
public final class k {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    public static final k f2878a = new k();

    private k() {
    }

    private final boolean a(byte[] bArr, String str) {
        if (bArr.length != str.length()) {
            return false;
        }
        Iterable iterableO = AbstractC0580h.o(bArr);
        if (!(iterableO instanceof Collection) || !((Collection) iterableO).isEmpty()) {
            Iterator it = iterableO.iterator();
            while (it.hasNext()) {
                int iA = ((C) it).a();
                if (((byte) str.charAt(iA)) != bArr[iA]) {
                    return false;
                }
            }
        }
        return true;
    }

    public static final int b(InputStream inputStream) {
        t2.j.f(inputStream, "stream");
        k kVar = f2878a;
        return (kVar.e(inputStream) << 8) | kVar.e(inputStream);
    }

    private final String c(byte[] bArr) {
        StringBuilder sb = new StringBuilder();
        for (byte b3 : bArr) {
            sb.append((char) (p.a(b3) & 65535));
        }
        String string = sb.toString();
        t2.j.e(string, "toString(...)");
        return string;
    }

    private final int d(InputStream inputStream) {
        int iE = e(inputStream);
        int iE2 = e(inputStream);
        return (e(inputStream) << 24) | (e(inputStream) << 16) | (iE2 << 8) | iE;
    }

    private final int e(InputStream inputStream) {
        return inputStream.read() & 255;
    }

    public static final C0563i f(InputStream inputStream) {
        k kVar;
        t2.j.f(inputStream, "stream");
        byte[] bArr = new byte[4];
        try {
        } catch (IOException e3) {
            e3.printStackTrace();
        }
        try {
            try {
                inputStream.read(bArr);
                kVar = f2878a;
            } catch (IOException e4) {
                e4.printStackTrace();
                inputStream.close();
            }
            if (!kVar.a(bArr, "RIFF")) {
                return null;
            }
            kVar.d(inputStream);
            inputStream.read(bArr);
            if (!kVar.a(bArr, "WEBP")) {
                try {
                    inputStream.close();
                } catch (IOException e5) {
                    e5.printStackTrace();
                }
                return null;
            }
            inputStream.read(bArr);
            String strC = kVar.c(bArr);
            int iHashCode = strC.hashCode();
            if (iHashCode != 2640674) {
                if (iHashCode != 2640718) {
                    if (iHashCode == 2640730 && strC.equals("VP8X")) {
                        C0563i c0563iI = kVar.i(inputStream);
                        try {
                            inputStream.close();
                        } catch (IOException e6) {
                            e6.printStackTrace();
                        }
                        return c0563iI;
                    }
                } else if (strC.equals("VP8L")) {
                    C0563i c0563iH = kVar.h(inputStream);
                    try {
                        inputStream.close();
                    } catch (IOException e7) {
                        e7.printStackTrace();
                    }
                    return c0563iH;
                }
            } else if (strC.equals("VP8 ")) {
                C0563i c0563iG = kVar.g(inputStream);
                try {
                    inputStream.close();
                } catch (IOException e8) {
                    e8.printStackTrace();
                }
                return c0563iG;
            }
            inputStream.close();
            return null;
        } finally {
            try {
                inputStream.close();
            } catch (IOException e9) {
                e9.printStackTrace();
            }
        }
    }

    private final C0563i g(InputStream inputStream) throws IOException {
        inputStream.skip(7L);
        int iE = e(inputStream);
        int iE2 = e(inputStream);
        int iE3 = e(inputStream);
        if (iE == 157 && iE2 == 1 && iE3 == 42) {
            return new C0563i(Integer.valueOf(b(inputStream)), Integer.valueOf(b(inputStream)));
        }
        return null;
    }

    private final C0563i h(InputStream inputStream) throws IOException {
        d(inputStream);
        if (e(inputStream) != 47) {
            return null;
        }
        int i3 = inputStream.read() & 255;
        int i4 = inputStream.read();
        return new C0563i(Integer.valueOf((i3 | ((i4 & 63) << 8)) + 1), Integer.valueOf((((inputStream.read() & 15) << 10) | ((inputStream.read() & 255) << 2) | ((i4 & 192) >> 6)) + 1));
    }

    private final C0563i i(InputStream inputStream) throws IOException {
        inputStream.skip(8L);
        return new C0563i(Integer.valueOf(j(inputStream) + 1), Integer.valueOf(j(inputStream) + 1));
    }

    private final int j(InputStream inputStream) {
        return (e(inputStream) << 16) | (e(inputStream) << 8) | e(inputStream);
    }
}
