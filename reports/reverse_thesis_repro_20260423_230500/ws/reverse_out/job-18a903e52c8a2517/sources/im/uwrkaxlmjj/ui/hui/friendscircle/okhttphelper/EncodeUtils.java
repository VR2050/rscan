package im.uwrkaxlmjj.ui.hui.friendscircle.okhttphelper;

import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.text.TextUtils;
import android.util.Base64;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import kotlin.UByte;

/* JADX INFO: loaded from: classes5.dex */
public class EncodeUtils {
    public static String byte2Hex(byte[] enc0) {
        StringBuilder sb = new StringBuilder("");
        for (byte b : enc0) {
            String strHex = Integer.toHexString(b & UByte.MAX_VALUE);
            sb.append(strHex.length() == 1 ? "0" + strHex : strHex);
        }
        return sb.toString().trim();
    }

    public static byte[] hex2Byte(String hex) {
        int byteLen = hex.length() / 2;
        byte[] ret = new byte[byteLen];
        for (int i = 0; i < byteLen; i++) {
            int m = (i * 2) + 1;
            int n = m + 1;
            int intVal = Integer.decode("0x" + hex.substring(i * 2, m) + hex.substring(m, n)).intValue();
            ret[i] = Byte.valueOf((byte) intVal).byteValue();
        }
        return ret;
    }

    /* JADX WARN: Unsupported multi-entry loop pattern (BACK_EDGE: B:12:0x0027 -> B:29:0x0037). Please report as a decompilation issue!!! */
    public static String imageToBase64(String path) {
        if (TextUtils.isEmpty(path)) {
            return null;
        }
        InputStream is = null;
        String result = null;
        try {
            try {
                try {
                    is = new FileInputStream(path);
                    byte[] data = new byte[is.available()];
                    is.read(data);
                    result = Base64.encodeToString(data, 0);
                    is.close();
                } catch (Exception e) {
                    e.printStackTrace();
                    if (is != null) {
                        is.close();
                    }
                    return result;
                }
            } catch (IOException e2) {
                e2.printStackTrace();
            }
            return result;
        } catch (Throwable th) {
            if (is != null) {
                try {
                    is.close();
                } catch (IOException e3) {
                    e3.printStackTrace();
                }
            }
            throw th;
        }
    }

    public static Bitmap stringtoBitmap(String strBase64) {
        String strTmp;
        if (strBase64.startsWith("data:image")) {
            strTmp = strBase64.substring(strBase64.indexOf("base64,") + 7);
        } else {
            strTmp = strBase64;
        }
        try {
            byte[] bitmapArray = Base64.decode(strTmp, 0);
            Bitmap bitmap = BitmapFactory.decodeByteArray(bitmapArray, 0, bitmapArray.length);
            return bitmap;
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }
}
