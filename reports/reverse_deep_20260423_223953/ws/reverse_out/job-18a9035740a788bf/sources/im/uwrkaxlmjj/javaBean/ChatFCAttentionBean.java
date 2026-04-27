package im.uwrkaxlmjj.javaBean;

import android.text.TextUtils;
import com.google.android.exoplayer2.upstream.DefaultLoadErrorHandlingPolicy;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;
import java.util.Locale;

/* JADX INFO: loaded from: classes2.dex */
public class ChatFCAttentionBean {
    public MsgDataBean interact_msg;
    public String msg_button_text;
    public int msg_time;
    public String msg_title;
    public String msg_url;

    public static class MsgDataBean {
        public long forum_id;
        public String forum_text;
        public int forum_type;
        public int is_followed;
        public String msg_content;
        public long msg_id;
        public int msg_time;
        public int with_id;
    }

    public static class PlanBodyBean {
        public String content;
        public String xStringOne;
    }

    public static class planDetailBean {
        public int expertType;
        public int planId;
        public int threadId;
        public int userId;
    }

    public String getTime() {
        String time = getFriendlyTimeSpanByNow(((long) this.interact_msg.msg_time) * 1000);
        return time;
    }

    public static String getFriendlyTimeSpanByNow(long millis) {
        long now = new Date().getTime();
        long span = now - millis;
        if (span < 0) {
            return String.format("%tc", Long.valueOf(millis));
        }
        if (span < DefaultLoadErrorHandlingPolicy.DEFAULT_TRACK_BLACKLIST_MS) {
            return "刚刚";
        }
        if (span < 3600000) {
            return String.format(Locale.getDefault(), "%d分钟前", Long.valueOf(span / DefaultLoadErrorHandlingPolicy.DEFAULT_TRACK_BLACKLIST_MS));
        }
        if (span < 86400000) {
            return String.format(Locale.getDefault(), "%d小时前", Long.valueOf(span / 3600000));
        }
        Calendar cal = Calendar.getInstance();
        int year = cal.get(1);
        SimpleDateFormat simpleDateFormat = new SimpleDateFormat("yyyy");
        String timeYear = simpleDateFormat.format(Long.valueOf(millis));
        int i = Integer.parseInt(timeYear);
        long wee = getWeeOfToday();
        long j = wee - 172800000;
        if (millis >= wee - 86400000) {
            SimpleDateFormat sdf = new SimpleDateFormat("HH:mm");
            String time_Date = "昨天  " + sdf.format(Long.valueOf(millis));
            return time_Date;
        }
        if (millis <= wee - 172800000 && year == i) {
            SimpleDateFormat sdf2 = new SimpleDateFormat("MM-dd HH:mm");
            String time_Date2 = sdf2.format(Long.valueOf(millis));
            return time_Date2;
        }
        SimpleDateFormat sdf3 = new SimpleDateFormat("yyyy-MM-dd HH:mm");
        String time_Date3 = sdf3.format(Long.valueOf(millis));
        return time_Date3;
    }

    private static long getWeeOfToday() {
        Calendar cal = Calendar.getInstance();
        cal.set(11, 0);
        cal.set(13, 0);
        cal.set(12, 0);
        cal.set(14, 0);
        return cal.getTimeInMillis();
    }

    public String getCreate24HEndTimeFormat() {
        StringBuilder sb;
        SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
        if (TextUtils.isEmpty(this.msg_time + "")) {
            sb = new StringBuilder();
            sb.append(new Date().getTime());
        } else {
            sb = new StringBuilder();
            sb.append(this.msg_time);
        }
        sb.append("");
        String time_Date = sdf.format(new Date(((long) Integer.parseInt(sb.toString())) * 1000));
        return time_Date;
    }
}
