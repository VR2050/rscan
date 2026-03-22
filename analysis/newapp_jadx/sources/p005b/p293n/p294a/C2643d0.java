package p005b.p293n.p294a;

import androidx.annotation.NonNull;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

/* renamed from: b.n.a.d0 */
/* loaded from: classes2.dex */
public final class C2643d0 {

    /* renamed from: a */
    public static final List<String> f7214a;

    /* renamed from: b */
    public static final Map<String, Integer> f7215b;

    /* renamed from: c */
    public static final List<String> f7216c;

    /* renamed from: d */
    public static final Map<String, String[]> f7217d;

    /* renamed from: e */
    public static final List<String> f7218e;

    /* renamed from: f */
    public static final Map<EnumC2639b0, List<String>> f7219f;

    /* renamed from: g */
    public static final Map<String, EnumC2639b0> f7220g;

    static {
        ArrayList arrayList = new ArrayList(12);
        f7214a = arrayList;
        HashMap hashMap = new HashMap(53);
        f7215b = hashMap;
        ArrayList arrayList2 = new ArrayList(4);
        f7216c = arrayList2;
        HashMap hashMap2 = new HashMap(10);
        f7217d = hashMap2;
        ArrayList arrayList3 = new ArrayList(2);
        f7218e = arrayList3;
        HashMap hashMap3 = new HashMap(9);
        f7219f = hashMap3;
        f7220g = new HashMap(25);
        arrayList.add("android.permission.SCHEDULE_EXACT_ALARM");
        arrayList.add("android.permission.MANAGE_EXTERNAL_STORAGE");
        arrayList.add("android.permission.REQUEST_INSTALL_PACKAGES");
        arrayList.add("android.permission.PICTURE_IN_PICTURE");
        arrayList.add("android.permission.SYSTEM_ALERT_WINDOW");
        arrayList.add("android.permission.WRITE_SETTINGS");
        arrayList.add("android.permission.ACCESS_NOTIFICATION_POLICY");
        arrayList.add("android.permission.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS");
        arrayList.add("android.permission.PACKAGE_USAGE_STATS");
        arrayList.add("android.permission.NOTIFICATION_SERVICE");
        arrayList.add("android.permission.BIND_NOTIFICATION_LISTENER_SERVICE");
        arrayList.add("android.permission.BIND_VPN_SERVICE");
        hashMap.put("android.permission.SCHEDULE_EXACT_ALARM", 31);
        hashMap.put("android.permission.MANAGE_EXTERNAL_STORAGE", 30);
        hashMap.put("android.permission.REQUEST_INSTALL_PACKAGES", 26);
        hashMap.put("android.permission.PICTURE_IN_PICTURE", 26);
        hashMap.put("android.permission.SYSTEM_ALERT_WINDOW", 23);
        hashMap.put("android.permission.WRITE_SETTINGS", 23);
        hashMap.put("android.permission.ACCESS_NOTIFICATION_POLICY", 23);
        hashMap.put("android.permission.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS", 23);
        hashMap.put("android.permission.PACKAGE_USAGE_STATS", 21);
        hashMap.put("android.permission.NOTIFICATION_SERVICE", 19);
        hashMap.put("android.permission.BIND_NOTIFICATION_LISTENER_SERVICE", 18);
        hashMap.put("android.permission.BIND_VPN_SERVICE", 14);
        hashMap.put("android.permission.READ_MEDIA_VISUAL_USER_SELECTED", 34);
        hashMap.put("android.permission.POST_NOTIFICATIONS", 33);
        hashMap.put("android.permission.NEARBY_WIFI_DEVICES", 33);
        hashMap.put("android.permission.BODY_SENSORS_BACKGROUND", 33);
        hashMap.put("android.permission.READ_MEDIA_IMAGES", 33);
        hashMap.put("android.permission.READ_MEDIA_VIDEO", 33);
        hashMap.put("android.permission.READ_MEDIA_AUDIO", 33);
        hashMap.put("android.permission.BLUETOOTH_SCAN", 31);
        hashMap.put("android.permission.BLUETOOTH_CONNECT", 31);
        hashMap.put("android.permission.BLUETOOTH_ADVERTISE", 31);
        hashMap.put("android.permission.ACCESS_BACKGROUND_LOCATION", 29);
        hashMap.put("android.permission.ACTIVITY_RECOGNITION", 29);
        hashMap.put("android.permission.ACCESS_MEDIA_LOCATION", 29);
        hashMap.put("android.permission.ACCEPT_HANDOVER", 28);
        hashMap.put("android.permission.ANSWER_PHONE_CALLS", 26);
        hashMap.put("android.permission.READ_PHONE_NUMBERS", 26);
        hashMap.put("com.android.permission.GET_INSTALLED_APPS", 23);
        hashMap.put("android.permission.READ_EXTERNAL_STORAGE", 23);
        hashMap.put("android.permission.WRITE_EXTERNAL_STORAGE", 23);
        hashMap.put("android.permission.CAMERA", 23);
        hashMap.put("android.permission.RECORD_AUDIO", 23);
        hashMap.put("android.permission.ACCESS_FINE_LOCATION", 23);
        hashMap.put("android.permission.ACCESS_COARSE_LOCATION", 23);
        hashMap.put("android.permission.READ_CONTACTS", 23);
        hashMap.put("android.permission.WRITE_CONTACTS", 23);
        hashMap.put("android.permission.GET_ACCOUNTS", 23);
        hashMap.put("android.permission.READ_CALENDAR", 23);
        hashMap.put("android.permission.WRITE_CALENDAR", 23);
        hashMap.put("android.permission.READ_PHONE_STATE", 23);
        hashMap.put("android.permission.CALL_PHONE", 23);
        hashMap.put("android.permission.READ_CALL_LOG", 23);
        hashMap.put("android.permission.WRITE_CALL_LOG", 23);
        hashMap.put("com.android.voicemail.permission.ADD_VOICEMAIL", 23);
        hashMap.put("android.permission.USE_SIP", 23);
        hashMap.put("android.permission.PROCESS_OUTGOING_CALLS", 23);
        hashMap.put("android.permission.BODY_SENSORS", 23);
        hashMap.put("android.permission.SEND_SMS", 23);
        hashMap.put("android.permission.RECEIVE_SMS", 23);
        hashMap.put("android.permission.READ_SMS", 23);
        hashMap.put("android.permission.RECEIVE_WAP_PUSH", 23);
        hashMap.put("android.permission.RECEIVE_MMS", 23);
        arrayList2.add("android.permission.NOTIFICATION_SERVICE");
        arrayList2.add("android.permission.BIND_NOTIFICATION_LISTENER_SERVICE");
        arrayList2.add("android.permission.BIND_VPN_SERVICE");
        arrayList2.add("android.permission.PICTURE_IN_PICTURE");
        hashMap2.put("android.permission.POST_NOTIFICATIONS", new String[]{"android.permission.NOTIFICATION_SERVICE"});
        hashMap2.put("android.permission.NEARBY_WIFI_DEVICES", new String[]{"android.permission.ACCESS_FINE_LOCATION"});
        hashMap2.put("android.permission.READ_MEDIA_IMAGES", new String[]{"android.permission.READ_EXTERNAL_STORAGE"});
        hashMap2.put("android.permission.READ_MEDIA_VIDEO", new String[]{"android.permission.READ_EXTERNAL_STORAGE"});
        hashMap2.put("android.permission.READ_MEDIA_AUDIO", new String[]{"android.permission.READ_EXTERNAL_STORAGE"});
        hashMap2.put("android.permission.BLUETOOTH_SCAN", new String[]{"android.permission.ACCESS_FINE_LOCATION"});
        hashMap2.put("android.permission.MANAGE_EXTERNAL_STORAGE", new String[]{"android.permission.READ_EXTERNAL_STORAGE", "android.permission.WRITE_EXTERNAL_STORAGE"});
        hashMap2.put("android.permission.ACTIVITY_RECOGNITION", new String[]{"android.permission.BODY_SENSORS"});
        hashMap2.put("android.permission.READ_PHONE_NUMBERS", new String[]{"android.permission.READ_PHONE_STATE"});
        arrayList3.add("android.permission.ACCESS_BACKGROUND_LOCATION");
        arrayList3.add("android.permission.BODY_SENSORS_BACKGROUND");
        List asList = Arrays.asList("android.permission.READ_EXTERNAL_STORAGE", "android.permission.WRITE_EXTERNAL_STORAGE");
        hashMap3.put(EnumC2639b0.STORAGE, asList);
        Iterator it = asList.iterator();
        while (it.hasNext()) {
            f7220g.put((String) it.next(), EnumC2639b0.STORAGE);
        }
        List<String> asList2 = Arrays.asList("android.permission.READ_CALENDAR", "android.permission.WRITE_CALENDAR");
        f7219f.put(EnumC2639b0.CALENDAR, asList2);
        Iterator<String> it2 = asList2.iterator();
        while (it2.hasNext()) {
            f7220g.put(it2.next(), EnumC2639b0.CALENDAR);
        }
        List<String> asList3 = Arrays.asList("android.permission.READ_CONTACTS", "android.permission.WRITE_CONTACTS");
        f7219f.put(EnumC2639b0.CONTACTS, asList3);
        Iterator<String> it3 = asList3.iterator();
        while (it3.hasNext()) {
            f7220g.put(it3.next(), EnumC2639b0.CONTACTS);
        }
        List<String> asList4 = Arrays.asList("android.permission.SEND_SMS", "android.permission.READ_SMS", "android.permission.RECEIVE_SMS", "android.permission.RECEIVE_WAP_PUSH", "android.permission.RECEIVE_MMS");
        f7219f.put(EnumC2639b0.SMS, asList4);
        Iterator<String> it4 = asList4.iterator();
        while (it4.hasNext()) {
            f7220g.put(it4.next(), EnumC2639b0.SMS);
        }
        List<String> asList5 = Arrays.asList("android.permission.ACCESS_COARSE_LOCATION", "android.permission.ACCESS_FINE_LOCATION", "android.permission.ACCESS_BACKGROUND_LOCATION");
        f7219f.put(EnumC2639b0.LOCATION, asList5);
        Iterator<String> it5 = asList5.iterator();
        while (it5.hasNext()) {
            f7220g.put(it5.next(), EnumC2639b0.LOCATION);
        }
        List<String> asList6 = Arrays.asList("android.permission.BODY_SENSORS", "android.permission.BODY_SENSORS_BACKGROUND");
        f7219f.put(EnumC2639b0.SENSORS, asList6);
        Iterator<String> it6 = asList6.iterator();
        while (it6.hasNext()) {
            f7220g.put(it6.next(), EnumC2639b0.SENSORS);
        }
        List<String> asList7 = Arrays.asList("android.permission.READ_CALL_LOG", "android.permission.WRITE_CALL_LOG");
        f7219f.put(EnumC2639b0.CALL_LOG, asList7);
        Iterator<String> it7 = asList7.iterator();
        while (it7.hasNext()) {
            f7220g.put(it7.next(), EnumC2639b0.CALL_LOG);
        }
        List<String> asList8 = Arrays.asList("android.permission.BLUETOOTH_SCAN", "android.permission.BLUETOOTH_CONNECT", "android.permission.BLUETOOTH_ADVERTISE", "android.permission.NEARBY_WIFI_DEVICES");
        f7219f.put(EnumC2639b0.NEARBY_DEVICES, asList8);
        Iterator<String> it8 = asList8.iterator();
        while (it8.hasNext()) {
            f7220g.put(it8.next(), EnumC2639b0.NEARBY_DEVICES);
        }
        List<String> asList9 = Arrays.asList("android.permission.READ_MEDIA_IMAGES", "android.permission.READ_MEDIA_VIDEO", "android.permission.READ_MEDIA_VISUAL_USER_SELECTED");
        f7219f.put(EnumC2639b0.IMAGE_AND_VIDEO_MEDIA, asList9);
        Iterator<String> it9 = asList9.iterator();
        while (it9.hasNext()) {
            f7220g.put(it9.next(), EnumC2639b0.IMAGE_AND_VIDEO_MEDIA);
        }
    }

    /* renamed from: a */
    public static int m3113a(@NonNull String str) {
        Integer num = f7215b.get(str);
        if (num == null) {
            return 0;
        }
        return num.intValue();
    }

    /* renamed from: b */
    public static boolean m3114b(@NonNull String str) {
        return C2645e0.m3119e(f7214a, str);
    }
}
