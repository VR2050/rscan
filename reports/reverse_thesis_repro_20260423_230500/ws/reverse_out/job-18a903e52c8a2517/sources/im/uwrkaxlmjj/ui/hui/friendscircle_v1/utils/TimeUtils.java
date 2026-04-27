package im.uwrkaxlmjj.ui.hui.friendscircle_v1.utils;

import com.blankj.utilcode.constant.TimeConstants;
import com.king.zxing.util.LogUtils;
import im.uwrkaxlmjj.messenger.LocaleController;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class TimeUtils {
    public static String getCurrentTime() {
        long timeStamp = System.currentTimeMillis();
        return String.valueOf(timeStamp);
    }

    public static String fcFormat2Date1(long timeStamp) {
        long timeStamp2;
        String strTime;
        if (String.valueOf(timeStamp).length() != 10) {
            timeStamp2 = timeStamp;
        } else {
            timeStamp2 = 1000 * timeStamp;
        }
        long curTimeMillis = System.currentTimeMillis();
        Date curDate = new Date(curTimeMillis);
        int todayHoursSeconds = curDate.getHours() * 60 * 60;
        int todayMinutesSeconds = curDate.getMinutes() * 60;
        int todaySeconds = curDate.getSeconds();
        int todayMillis = (todayHoursSeconds + todayMinutesSeconds + todaySeconds) * 1000;
        long todayStartMillis = curTimeMillis - ((long) todayMillis);
        if (timeStamp2 >= todayStartMillis) {
            Date date = new Date(timeStamp2);
            if (date.getMinutes() < 10) {
                strTime = date.getHours() + ":0" + date.getMinutes();
            } else {
                strTime = date.getHours() + LogUtils.COLON + date.getMinutes();
            }
            return LocaleController.getString("today", R.string.today) + strTime;
        }
        long timeStamp3 = timeStamp2;
        long yesterdayStartMillis = todayStartMillis - ((long) TimeConstants.DAY);
        if (timeStamp3 >= yesterdayStartMillis) {
            Date date2 = new Date(timeStamp3);
            if (date2.getMinutes() < 10) {
                return LocaleController.getString("Yesterday", R.string.Yesterday) + date2.getHours() + ":0" + date2.getMinutes();
            }
            return LocaleController.getString("Yesterday", R.string.Yesterday) + date2.getHours() + LogUtils.COLON + date2.getMinutes();
        }
        String strTime2 = timeFormat(timeStamp3, "yyyy-MM-dd HH:mm");
        return strTime2;
    }

    public static String fcFormat2Date(long timeStamp) {
        long timeStamp2;
        if (String.valueOf(timeStamp).length() != 10) {
            timeStamp2 = timeStamp;
        } else {
            timeStamp2 = timeStamp * 1000;
        }
        Date date = new Date(timeStamp2);
        Calendar calendar = Calendar.getInstance();
        calendar.get(5);
        long now = calendar.getTimeInMillis();
        calendar.setTime(date);
        long past = calendar.getTimeInMillis();
        long time = (now - past) / 1000;
        if (time <= 60) {
            return LocaleController.getString("fc_time_recently", R.string.fc_time_recently);
        }
        if (time <= 3600) {
            return String.format(LocaleController.getString(R.string.fc_time_format_minute), Long.valueOf(time / 60));
        }
        if (time <= 86400) {
            return String.format(LocaleController.getString(R.string.fc_time_format_hour), Long.valueOf(time / 3600));
        }
        if (time <= 172800) {
            return String.format(LocaleController.getString(R.string.fc_time_format_yesterday), timeFormat(timeStamp2, "HH:mm"));
        }
        calendar.clear();
        calendar.setTime(new Date(now));
        int nowYear = calendar.get(1);
        calendar.setTime(date);
        int pastYear = calendar.get(1);
        if (pastYear == nowYear) {
            return timeFormat(timeStamp2, "MM-dd HH:mm");
        }
        return timeFormat(timeStamp2, "yyyy-MM-dd HH:mm");
    }

    public static Date getDate(String time) {
        SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm");
        try {
            Date date = sdf.parse(time);
            return date;
        } catch (ParseException e) {
            e.printStackTrace();
            return null;
        }
    }

    public static String setDate(String timeStamp) {
        SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm");
        if (timeStamp == null || timeStamp.isEmpty() || timeStamp.equals("null")) {
            return "";
        }
        return sdf.format(new Date(Long.valueOf(timeStamp).longValue()));
    }

    public static String fcFormat(Date timeStamp) {
        String strTime;
        if (timeStamp == null) {
            return "";
        }
        long curTimeMillis = System.currentTimeMillis();
        Date curDate = new Date(curTimeMillis);
        int todayHoursSeconds = curDate.getHours() * 60 * 60;
        int todayMinutesSeconds = curDate.getMinutes() * 60;
        int todaySeconds = curDate.getSeconds();
        int todayMillis = (todayHoursSeconds + todayMinutesSeconds + todaySeconds) * 1000;
        long todayStartMillis = curTimeMillis - ((long) todayMillis);
        if (timeStamp.getTime() >= todayStartMillis) {
            if (timeStamp.getMinutes() < 10) {
                strTime = timeStamp.getHours() + ":0" + timeStamp.getMinutes();
            } else {
                strTime = timeStamp.getHours() + LogUtils.COLON + timeStamp.getMinutes();
            }
            return LocaleController.getString("MessageScheduleToday", R.string.MessageScheduleToday) + strTime;
        }
        long yesterdayStartMillis = todayStartMillis - ((long) TimeConstants.DAY);
        if (timeStamp.getTime() < yesterdayStartMillis) {
            long yesterdayBeforeStartMillis = yesterdayStartMillis - ((long) TimeConstants.DAY);
            if (timeStamp.getTime() >= yesterdayBeforeStartMillis) {
                if (timeStamp.getMinutes() < 10) {
                    return LocaleController.getString("date_before_yesterday", R.string.date_before_yesterday) + timeStamp.getHours() + ":0" + timeStamp.getMinutes();
                }
                return LocaleController.getString("date_before_yesterday", R.string.date_before_yesterday) + timeStamp.getHours() + LogUtils.COLON + timeStamp.getMinutes();
            }
            long yesterdayBeforeStartMillis2 = timeStamp.getTime();
            String strTime2 = timeFormat(yesterdayBeforeStartMillis2, "yyyy-MM-dd ");
            return strTime2;
        }
        if (timeStamp.getMinutes() < 10) {
            return LocaleController.getString("Yesterday", R.string.Yesterday) + timeStamp.getHours() + ":0" + timeStamp.getMinutes();
        }
        return LocaleController.getString("Yesterday", R.string.Yesterday) + timeStamp.getHours() + LogUtils.COLON + timeStamp.getMinutes();
    }

    public static String timeFormat(long timeStamp, String format) {
        SimpleDateFormat sf = new SimpleDateFormat(format);
        return sf.format(Long.valueOf(timeStamp));
    }

    public static String YearMon(long timeStamp) {
        SimpleDateFormat sdr = new SimpleDateFormat("yyyy年MM月");
        String times = sdr.format(new Date(1000 * timeStamp));
        return times;
    }

    public static int getAgeByBirthday(Date birthday) {
        Calendar cal = Calendar.getInstance();
        if (cal.before(birthday)) {
            throw new IllegalArgumentException("The birthDay is before Now.It's unbelievable!");
        }
        int yearNow = cal.get(1);
        int monthNow = cal.get(2) + 1;
        int dayOfMonthNow = cal.get(5);
        cal.setTime(birthday);
        int yearBirth = cal.get(1);
        int monthBirth = cal.get(2) + 1;
        int dayOfMonthBirth = cal.get(5);
        int age = yearNow - yearBirth;
        if (monthNow <= monthBirth) {
            if (monthNow == monthBirth) {
                if (dayOfMonthNow < dayOfMonthBirth) {
                    return age - 1;
                }
                return age;
            }
            return age - 1;
        }
        return age;
    }
}
