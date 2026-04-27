package im.uwrkaxlmjj.ui.utils.number;

import androidx.exifinterface.media.ExifInterface;
import java.text.SimpleDateFormat;
import java.util.Date;

/* JADX INFO: loaded from: classes5.dex */
public class TimeUtils {
    public static long getTimeLong() {
        return System.currentTimeMillis();
    }

    public static int getTimeInt(String filter) {
        SimpleDateFormat format = new SimpleDateFormat(filter);
        String time = format.format(new Date());
        return Integer.parseInt(time);
    }

    public static String getTimeStringE() {
        SimpleDateFormat format = new SimpleDateFormat(ExifInterface.LONGITUDE_EAST);
        String time = format.format(new Date());
        return time;
    }

    public static int getTimeInt(String StringTime, String filter) {
        SimpleDateFormat format = new SimpleDateFormat(filter);
        String time = format.format(new Date(getTimeLong("yyyy-MM-dd HH:mm:ss", StringTime).longValue()));
        return Integer.parseInt(time);
    }

    public static String getTimeStringE(String stringTime) {
        SimpleDateFormat format = new SimpleDateFormat(ExifInterface.LONGITUDE_EAST);
        String time = format.format(new Date(getTimeLong("yyyy-MM-dd HH:mm:ss", stringTime).longValue()));
        return time;
    }

    public static final String getTimeString() {
        SimpleDateFormat format = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
        return format.format(new Date(getTimeLong()));
    }

    public static final String getTimeString(long time) {
        SimpleDateFormat format = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
        return format.format(new Date(time));
    }

    public static final String getTimeString(long time, String filter) {
        SimpleDateFormat format = new SimpleDateFormat(filter);
        return format.format(new Date(time));
    }

    public static final String getTimeString(String filter) {
        SimpleDateFormat format = new SimpleDateFormat(filter);
        return format.format(new Date(getTimeLong()));
    }

    public static Long getTimeLong(String filter, String date) {
        try {
            SimpleDateFormat format = new SimpleDateFormat(filter);
            Date dateTime = format.parse(date);
            return Long.valueOf(dateTime.getTime());
        } catch (Exception e) {
            e.printStackTrace();
            return 0L;
        }
    }

    public static String getTimeLocalString(String filter, String data, String filterInside) {
        Long timeLong = getTimeLong(filter, data);
        return getTimeString(timeLong.longValue(), filterInside);
    }
}
