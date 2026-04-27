package im.uwrkaxlmjj.ui.utils;

import android.text.TextUtils;
import android.util.Base64;
import com.snail.antifake.deviceid.ShellAdbUtils;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/* JADX INFO: loaded from: classes5.dex */
public class AesUtils {
    public static String encrypt(String text) {
        if (TextUtils.isEmpty(text)) {
            return text;
        }
        try {
            byte[] result = encryptInternal(text);
            String pass = new String(Base64.encode(result, 0));
            return pass.replaceAll(ShellAdbUtils.COMMAND_LINE_END, "");
        } catch (Exception e) {
            e.printStackTrace();
            return "";
        }
    }

    public static String encryptToBase64(String text) {
        if (TextUtils.isEmpty(text)) {
            return text;
        }
        try {
            byte[] result = encryptInternal(text);
            return Base64.encodeToString(result, 2);
        } catch (Exception e) {
            e.printStackTrace();
            return "";
        }
    }

    public static byte[] encryptInternal(String text) throws Exception {
        SecretKeySpec secretKeySpec = new SecretKeySpec("Wu^tdJ92hFBqb7kz".getBytes(), "AES");
        IvParameterSpec ivSpec = new IvParameterSpec("0392039203920300".getBytes());
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(1, secretKeySpec, ivSpec);
        return cipher.doFinal(text.getBytes("UTF-8"));
    }

    public static String decrypt(String content) {
        if (TextUtils.isEmpty(content)) {
            return content;
        }
        try {
            byte[] result = decryptInternal(content);
            return new String(result, "UTF-8");
        } catch (Exception e) {
            e.printStackTrace();
            return "";
        }
    }

    private static byte[] decryptInternal(String content) throws Exception {
        byte[] byteMi = Base64.decode(content, 0);
        SecretKeySpec secretKeySpec = new SecretKeySpec("Wu^tdJ92hFBqb7kz".getBytes(), "AES");
        IvParameterSpec ivSpec = new IvParameterSpec("0392039203920300".getBytes());
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(2, secretKeySpec, ivSpec);
        return cipher.doFinal(byteMi);
    }

    public static byte[] decryptYunceng(String content) throws Exception {
        byte[] byteMi = Base64.decode(content, 0);
        SecretKeySpec secretKeySpec = new SecretKeySpec("2018201820182018".getBytes(), "AES");
        IvParameterSpec ivSpec = new IvParameterSpec("1234567887654321".getBytes());
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(2, secretKeySpec, ivSpec);
        return cipher.doFinal(byteMi);
    }
}
