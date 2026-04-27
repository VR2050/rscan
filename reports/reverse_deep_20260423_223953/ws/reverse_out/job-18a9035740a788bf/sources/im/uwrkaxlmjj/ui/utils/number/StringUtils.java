package im.uwrkaxlmjj.ui.utils.number;

import java.text.SimpleDateFormat;
import java.util.Random;

/* JADX INFO: loaded from: classes5.dex */
public class StringUtils {
    private static final String base = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    private static SimpleDateFormat simpleDateFormat = new SimpleDateFormat("yyyy-MM-dd hh:mm:ss EEEE");

    public static String getRandomString(int length) {
        Random random = new Random();
        StringBuffer sb = new StringBuffer();
        for (int i = 0; i < length; i++) {
            int number = random.nextInt(base.length());
            sb.append(base.charAt(number));
        }
        return sb.toString();
    }

    public static String getTradeNo(int uid, int time) {
        return "android_" + uid + getRandomString(16) + time;
    }

    public static String getNonceStr(int time) {
        return getRandomString(20) + time;
    }

    public static String getWithdrawStr() {
        return "android_" + getRandomString(8);
    }
}
