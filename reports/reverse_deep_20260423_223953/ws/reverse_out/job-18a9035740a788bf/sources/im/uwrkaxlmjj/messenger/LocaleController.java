package im.uwrkaxlmjj.messenger;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.SharedPreferences;
import android.content.res.Configuration;
import android.telephony.TelephonyManager;
import android.text.TextUtils;
import android.text.format.DateFormat;
import android.util.Xml;
import com.alibaba.fastjson.parser.JSONLexer;
import com.google.android.exoplayer2.offline.DownloadAction;
import com.google.android.exoplayer2.text.ttml.TtmlNode;
import com.king.zxing.util.LogUtils;
import com.snail.antifake.deviceid.ShellAdbUtils;
import im.uwrkaxlmjj.messenger.time.FastDateFormat;
import im.uwrkaxlmjj.tgnet.ConnectionsManager;
import im.uwrkaxlmjj.tgnet.RequestDelegate;
import im.uwrkaxlmjj.tgnet.TLObject;
import im.uwrkaxlmjj.tgnet.TLRPC;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.text.NumberFormat;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Currency;
import java.util.Date;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.TimeZone;
import kotlin.text.Typography;
import org.webrtc.mozi.CodecMonitorHelper;
import org.webrtc.mozi.ScreenAudioCapturer;
import org.xmlpull.v1.XmlPullParser;
import org.xmlpull.v1.XmlPullParserException;

/* JADX INFO: loaded from: classes2.dex */
public class LocaleController {
    static final int QUANTITY_FEW = 8;
    static final int QUANTITY_MANY = 16;
    static final int QUANTITY_ONE = 2;
    static final int QUANTITY_OTHER = 0;
    static final int QUANTITY_TWO = 4;
    static final int QUANTITY_ZERO = 1;
    private static Boolean useImperialSystemType;
    public FastDateFormat chatDate;
    public FastDateFormat chatFullDate;
    private HashMap<String, String> currencyValues;
    private Locale currentLocale;
    private LocaleInfo currentLocaleInfo;
    private PluralRules currentPluralRules;
    private String currentSystemLocale;
    public FastDateFormat formatterBannedUntil;
    public FastDateFormat formatterBannedUntilThisYear;
    public FastDateFormat formatterDay;
    public FastDateFormat formatterDayMonth;
    public FastDateFormat formatterDayNoly;
    public FastDateFormat formatterScheduleDay;
    public FastDateFormat formatterScheduleYear;
    public FastDateFormat formatterStats;
    public FastDateFormat formatterWeek;
    public FastDateFormat formatterYear;
    public FastDateFormat formatterYearMax;
    private String languageOverride;
    private boolean loadingRemoteLanguages;
    private boolean reloadLastFile;
    private HashMap<String, String> ruTranslitChars;
    private Locale systemDefaultLocale;
    private HashMap<String, String> translitChars;
    public static boolean isRTL = false;
    public static int nameDisplayOrder = 1;
    public static boolean is24HourFormat = false;
    private static volatile LocaleController Instance = null;
    public FastDateFormat[] formatterScheduleSend = new FastDateFormat[6];
    private HashMap<String, PluralRules> allRules = new HashMap<>();
    private HashMap<String, String> localeValues = new HashMap<>();
    private boolean changingConfiguration = false;
    public ArrayList<LocaleInfo> languages = new ArrayList<>();
    public ArrayList<LocaleInfo> unofficialLanguages = new ArrayList<>();
    public ArrayList<LocaleInfo> remoteLanguages = new ArrayList<>();
    public HashMap<String, LocaleInfo> remoteLanguagesDict = new HashMap<>();
    public HashMap<String, LocaleInfo> languagesDict = new HashMap<>();
    private ArrayList<LocaleInfo> otherLanguages = new ArrayList<>();

    public static abstract class PluralRules {
        abstract int quantityForNumber(int i);
    }

    /* JADX INFO: Access modifiers changed from: private */
    class TimeZoneChangedReceiver extends BroadcastReceiver {
        private TimeZoneChangedReceiver() {
        }

        @Override // android.content.BroadcastReceiver
        public void onReceive(Context context, Intent intent) {
            ApplicationLoader.applicationHandler.post(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$LocaleController$TimeZoneChangedReceiver$mVczzMg6b7LebcxXf-GxIjyZl3A
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$onReceive$0$LocaleController$TimeZoneChangedReceiver();
                }
            });
        }

        public /* synthetic */ void lambda$onReceive$0$LocaleController$TimeZoneChangedReceiver() {
            if (!LocaleController.this.formatterDayMonth.getTimeZone().equals(TimeZone.getDefault())) {
                LocaleController.getInstance().recreateFormatters();
            }
        }
    }

    public static class LocaleInfo {
        public String baseLangCode;
        public int baseVersion;
        public boolean builtIn;
        public boolean isRtl;
        public String name;
        public String nameEnglish;
        public String pathToFile;
        public String pluralLangCode;
        public int serverIndex;
        public String shortName;
        public int version;

        public String getSaveString() {
            String str = this.baseLangCode;
            if (str == null) {
                str = "";
            }
            if (TextUtils.isEmpty(this.pluralLangCode)) {
                String str2 = this.shortName;
            } else {
                String str3 = this.pluralLangCode;
            }
            return this.name + LogUtils.VERTICAL + this.nameEnglish + LogUtils.VERTICAL + this.shortName + LogUtils.VERTICAL + this.pathToFile + LogUtils.VERTICAL + this.version + LogUtils.VERTICAL + str + LogUtils.VERTICAL + this.pluralLangCode + LogUtils.VERTICAL + (this.isRtl ? 1 : 0) + LogUtils.VERTICAL + this.baseVersion + LogUtils.VERTICAL + this.serverIndex;
        }

        public static LocaleInfo createWithString(String string) {
            if (string == null || string.length() == 0) {
                return null;
            }
            String[] args = string.split("\\|");
            LocaleInfo localeInfo = null;
            if (args.length >= 4) {
                localeInfo = new LocaleInfo();
                localeInfo.name = args[0];
                localeInfo.nameEnglish = args[1];
                localeInfo.shortName = args[2].toLowerCase();
                localeInfo.pathToFile = args[3];
                if (args.length >= 5) {
                    localeInfo.version = Utilities.parseInt(args[4]).intValue();
                }
                localeInfo.baseLangCode = args.length >= 6 ? args[5] : "";
                localeInfo.pluralLangCode = args.length >= 7 ? args[6] : localeInfo.shortName;
                if (args.length >= 9) {
                    localeInfo.baseVersion = Utilities.parseInt(args[8]).intValue();
                }
                if (args.length >= 10) {
                    localeInfo.serverIndex = Utilities.parseInt(args[9]).intValue();
                } else {
                    localeInfo.serverIndex = Integer.MAX_VALUE;
                }
                if (!TextUtils.isEmpty(localeInfo.baseLangCode)) {
                    localeInfo.baseLangCode = localeInfo.baseLangCode.replace("-", "_");
                }
            }
            return localeInfo;
        }

        public File getPathToFile() {
            if (isRemote()) {
                return new File(ApplicationLoader.getFilesDirFixed(), "remote_" + this.shortName + ".xml");
            }
            if (isUnofficial()) {
                return new File(ApplicationLoader.getFilesDirFixed(), "unofficial_" + this.shortName + ".xml");
            }
            if (TextUtils.isEmpty(this.pathToFile)) {
                return null;
            }
            return new File(this.pathToFile);
        }

        public File getPathToBaseFile() {
            if (isUnofficial()) {
                return new File(ApplicationLoader.getFilesDirFixed(), "unofficial_base_" + this.shortName + ".xml");
            }
            return null;
        }

        public String getKey() {
            if (this.pathToFile != null && !isRemote() && !isUnofficial()) {
                return "local_" + this.shortName;
            }
            if (isUnofficial()) {
                return "unofficial_" + this.shortName;
            }
            return this.shortName;
        }

        public boolean hasBaseLang() {
            return (!isUnofficial() || TextUtils.isEmpty(this.baseLangCode) || this.baseLangCode.equals(this.shortName)) ? false : true;
        }

        public boolean isRemote() {
            return "remote".equals(this.pathToFile);
        }

        public boolean isUnofficial() {
            return "unofficial".equals(this.pathToFile);
        }

        public boolean isLocal() {
            return (TextUtils.isEmpty(this.pathToFile) || isRemote() || isUnofficial()) ? false : true;
        }

        public boolean isBuiltIn() {
            return this.builtIn;
        }

        public String getLangCode() {
            return this.shortName.replace("_", "-");
        }

        public String getBaseLangCode() {
            String str = this.baseLangCode;
            return str == null ? "" : str.replace("_", "-");
        }
    }

    public static LocaleController getInstance() {
        LocaleController localInstance = Instance;
        if (localInstance == null) {
            synchronized (LocaleController.class) {
                localInstance = Instance;
                if (localInstance == null) {
                    LocaleController localeController = new LocaleController();
                    localInstance = localeController;
                    Instance = localeController;
                }
            }
        }
        return localInstance;
    }

    /* JADX WARN: Removed duplicated region for block: B:38:0x006d  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.String getLanguageShortNametoBdTransName() {
        /*
            r4 = this;
            im.uwrkaxlmjj.messenger.LocaleController$LocaleInfo r0 = r4.currentLocaleInfo
            java.lang.String r0 = r0.shortName
            int r1 = r0.hashCode()
            r2 = 3201(0xc81, float:4.486E-42)
            java.lang.String r3 = "de"
            if (r1 == r2) goto L65
            r2 = 3276(0xccc, float:4.59E-42)
            if (r1 == r2) goto L5b
            r2 = 3383(0xd37, float:4.74E-42)
            if (r1 == r2) goto L51
            r2 = 3428(0xd64, float:4.804E-42)
            if (r1 == r2) goto L47
            r2 = 3763(0xeb3, float:5.273E-42)
            if (r1 == r2) goto L3d
            r2 = 115862300(0x6e7eb1c, float:8.7238005E-35)
            if (r1 == r2) goto L33
            r2 = 115862836(0x6e7ed34, float:8.724108E-35)
            if (r1 == r2) goto L29
        L28:
            goto L6d
        L29:
            java.lang.String r1 = "zh_tw"
            boolean r0 = r0.equals(r1)
            if (r0 == 0) goto L28
            r0 = 6
            goto L6e
        L33:
            java.lang.String r1 = "zh_cn"
            boolean r0 = r0.equals(r1)
            if (r0 == 0) goto L28
            r0 = 5
            goto L6e
        L3d:
            java.lang.String r1 = "vi"
            boolean r0 = r0.equals(r1)
            if (r0 == 0) goto L28
            r0 = 0
            goto L6e
        L47:
            java.lang.String r1 = "ko"
            boolean r0 = r0.equals(r1)
            if (r0 == 0) goto L28
            r0 = 3
            goto L6e
        L51:
            java.lang.String r1 = "ja"
            boolean r0 = r0.equals(r1)
            if (r0 == 0) goto L28
            r0 = 4
            goto L6e
        L5b:
            java.lang.String r1 = "fr"
            boolean r0 = r0.equals(r1)
            if (r0 == 0) goto L28
            r0 = 1
            goto L6e
        L65:
            boolean r0 = r0.equals(r3)
            if (r0 == 0) goto L28
            r0 = 2
            goto L6e
        L6d:
            r0 = -1
        L6e:
            switch(r0) {
                case 0: goto L84;
                case 1: goto L81;
                case 2: goto L80;
                case 3: goto L7d;
                case 4: goto L7a;
                case 5: goto L77;
                case 6: goto L74;
                default: goto L71;
            }
        L71:
            java.lang.String r0 = "en"
            return r0
        L74:
            java.lang.String r0 = "cht"
            return r0
        L77:
            java.lang.String r0 = "zh"
            return r0
        L7a:
            java.lang.String r0 = "jp"
            return r0
        L7d:
            java.lang.String r0 = "kor"
            return r0
        L80:
            return r3
        L81:
            java.lang.String r0 = "fra"
            return r0
        L84:
            java.lang.String r0 = "vie"
            return r0
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.messenger.LocaleController.getLanguageShortNametoBdTransName():java.lang.String");
    }

    public LocaleController() {
        addRules(new String[]{"bem", "brx", "da", "de", "el", "en", "eo", "es", "et", "fi", "fo", "gl", "he", "iw", "it", "nb", "nl", "nn", "no", "sv", "af", "bg", "bn", "ca", "eu", "fur", "fy", "gu", "ha", "is", "ku", "lb", "ml", "mr", "nah", "ne", "om", "or", "pa", "pap", "ps", "so", "sq", CodecMonitorHelper.FORMAT_SW, "ta", "te", "tk", "ur", "zu", "mn", "gsw", "chr", "rm", "pt", "an", "ast"}, new PluralRules_One());
        addRules(new String[]{"cs", "sk"}, new PluralRules_Czech());
        addRules(new String[]{"ff", "fr", "kab"}, new PluralRules_French());
        addRules(new String[]{"hr", "ru", "sr", "uk", "be", "bs", ShellAdbUtils.COMMAND_SH}, new PluralRules_Balkan());
        addRules(new String[]{"lv"}, new PluralRules_Latvian());
        addRules(new String[]{"lt"}, new PluralRules_Lithuanian());
        addRules(new String[]{"pl"}, new PluralRules_Polish());
        addRules(new String[]{"ro", "mo"}, new PluralRules_Romanian());
        addRules(new String[]{"sl"}, new PluralRules_Slovenian());
        addRules(new String[]{"ar"}, new PluralRules_Arabic());
        addRules(new String[]{"mk"}, new PluralRules_Macedonian());
        addRules(new String[]{"cy"}, new PluralRules_Welsh());
        addRules(new String[]{TtmlNode.TAG_BR}, new PluralRules_Breton());
        addRules(new String[]{"lag"}, new PluralRules_Langi());
        addRules(new String[]{"shi"}, new PluralRules_Tachelhit());
        addRules(new String[]{"mt"}, new PluralRules_Maltese());
        addRules(new String[]{"ga", "se", "sma", "smi", "smj", "smn", "sms"}, new PluralRules_Two());
        addRules(new String[]{"ak", "am", "bh", "fil", "tl", "guw", "hi", "ln", "mg", "nso", "ti", "wa"}, new PluralRules_Zero());
        addRules(new String[]{"az", "bm", "fa", "ig", "hu", "ja", "kde", "kea", "ko", "my", "ses", "sg", "to", "tr", "vi", "wo", "yo", "zh", "bo", "dz", TtmlNode.ATTR_ID, "jv", "jw", "ka", "km", "kn", "ms", "th", "in"}, new PluralRules_None());
        LocaleInfo localeInfo = new LocaleInfo();
        localeInfo.name = "English";
        localeInfo.nameEnglish = "English";
        localeInfo.pluralLangCode = "en";
        localeInfo.shortName = "en";
        localeInfo.pathToFile = null;
        localeInfo.builtIn = true;
        this.languages.add(localeInfo);
        this.languagesDict.put(localeInfo.shortName, localeInfo);
        LocaleInfo localeInfo2 = new LocaleInfo();
        localeInfo2.name = "Français";
        localeInfo2.nameEnglish = "French";
        localeInfo2.pluralLangCode = "fr";
        localeInfo2.shortName = "fr";
        localeInfo2.builtIn = true;
        this.languages.add(localeInfo2);
        this.languagesDict.put(localeInfo2.shortName, localeInfo2);
        LocaleInfo localeInfo3 = new LocaleInfo();
        localeInfo3.name = "Português";
        localeInfo3.nameEnglish = "Portuguese";
        localeInfo3.pluralLangCode = "pt";
        localeInfo3.shortName = "pt";
        localeInfo3.builtIn = true;
        this.languages.add(localeInfo3);
        this.languagesDict.put(localeInfo3.shortName, localeInfo3);
        LocaleInfo localeInfo4 = new LocaleInfo();
        localeInfo4.name = "Ελληνικά";
        localeInfo4.nameEnglish = "Greek";
        localeInfo4.pluralLangCode = "el";
        localeInfo4.shortName = "el";
        localeInfo4.builtIn = true;
        this.languages.add(localeInfo4);
        this.languagesDict.put(localeInfo4.shortName, localeInfo4);
        LocaleInfo localeInfo5 = new LocaleInfo();
        localeInfo5.name = "Bahasa Indonesia";
        localeInfo5.nameEnglish = "Indonesian";
        localeInfo5.pluralLangCode = "in-rID";
        localeInfo5.shortName = "in-rID";
        localeInfo5.builtIn = true;
        this.languages.add(localeInfo5);
        this.languagesDict.put(localeInfo5.shortName, localeInfo5);
        LocaleInfo localeInfo6 = new LocaleInfo();
        localeInfo6.name = "Melayu";
        localeInfo6.nameEnglish = "Malay";
        localeInfo6.pluralLangCode = "ms";
        localeInfo6.shortName = "ms";
        localeInfo6.builtIn = true;
        this.languages.add(localeInfo6);
        this.languagesDict.put(localeInfo6.shortName, localeInfo6);
        LocaleInfo localeInfo7 = new LocaleInfo();
        localeInfo7.name = "Tiếng Việt";
        localeInfo7.nameEnglish = "Vietnamese";
        localeInfo7.pluralLangCode = "vi";
        localeInfo7.shortName = "vi";
        localeInfo7.pathToFile = null;
        localeInfo7.builtIn = true;
        this.languages.add(localeInfo7);
        this.languagesDict.put(localeInfo7.shortName, localeInfo7);
        LocaleInfo localeInfo8 = new LocaleInfo();
        localeInfo8.name = "日语";
        localeInfo8.nameEnglish = "Japanese";
        localeInfo8.pluralLangCode = "ja";
        localeInfo8.shortName = "ja";
        localeInfo8.pathToFile = null;
        localeInfo8.builtIn = true;
        this.languages.add(localeInfo8);
        this.languagesDict.put(localeInfo8.shortName, localeInfo8);
        LocaleInfo localeInfo9 = new LocaleInfo();
        localeInfo9.name = "हिंदी";
        localeInfo9.nameEnglish = "Hindi";
        localeInfo9.pluralLangCode = "hi";
        localeInfo9.shortName = "hi";
        localeInfo9.pathToFile = null;
        localeInfo9.builtIn = true;
        this.languages.add(localeInfo9);
        this.languagesDict.put(localeInfo9.shortName, localeInfo9);
        LocaleInfo localeInfo10 = new LocaleInfo();
        localeInfo10.name = "简体中文";
        localeInfo10.nameEnglish = "Simplified Chinese";
        localeInfo10.shortName = "zh_cn";
        localeInfo10.pathToFile = null;
        this.languages.add(localeInfo10);
        this.languagesDict.put(localeInfo10.shortName, localeInfo10);
        LocaleInfo localeInfo11 = new LocaleInfo();
        localeInfo11.name = "繁體中文";
        localeInfo11.nameEnglish = "Traditional Chinese";
        localeInfo11.shortName = "zh_tw";
        localeInfo11.pathToFile = null;
        this.languages.add(localeInfo11);
        this.languagesDict.put(localeInfo11.shortName, localeInfo11);
        loadOtherLanguages();
        if (this.remoteLanguages.isEmpty()) {
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$LocaleController$Im2qDJu2UqeIolKecAbSGTbUpN8
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$new$0$LocaleController();
                }
            });
        }
        for (int a = 0; a < this.otherLanguages.size(); a++) {
            LocaleInfo locale = this.otherLanguages.get(a);
            this.languages.add(locale);
            this.languagesDict.put(locale.getKey(), locale);
        }
        for (int a2 = 0; a2 < this.remoteLanguages.size(); a2++) {
            LocaleInfo locale2 = this.remoteLanguages.get(a2);
            LocaleInfo existingLocale = getLanguageFromDict(locale2.getKey());
            if (existingLocale != null) {
                existingLocale.pathToFile = locale2.pathToFile;
                existingLocale.version = locale2.version;
                existingLocale.baseVersion = locale2.baseVersion;
                existingLocale.serverIndex = locale2.serverIndex;
                this.remoteLanguages.set(a2, existingLocale);
            } else {
                this.languages.add(locale2);
                this.languagesDict.put(locale2.getKey(), locale2);
            }
        }
        for (int a3 = 0; a3 < this.unofficialLanguages.size(); a3++) {
            LocaleInfo locale3 = this.unofficialLanguages.get(a3);
            LocaleInfo existingLocale2 = getLanguageFromDict(locale3.getKey());
            if (existingLocale2 != null) {
                existingLocale2.pathToFile = locale3.pathToFile;
                existingLocale2.version = locale3.version;
                existingLocale2.baseVersion = locale3.baseVersion;
                existingLocale2.serverIndex = locale3.serverIndex;
                this.unofficialLanguages.set(a3, existingLocale2);
            } else {
                this.languagesDict.put(locale3.getKey(), locale3);
            }
        }
        this.systemDefaultLocale = Locale.getDefault();
        is24HourFormat = DateFormat.is24HourFormat(ApplicationLoader.applicationContext);
        LocaleInfo currentInfo = null;
        boolean override = false;
        try {
            SharedPreferences preferences = MessagesController.getGlobalMainSettings();
            String lang = preferences.getString("language", null);
            if (lang != null && (currentInfo = getLanguageFromDict(lang)) != null) {
                override = true;
            }
            if (currentInfo == null && this.systemDefaultLocale.getLanguage() != null) {
                currentInfo = getLanguageFromDict(this.systemDefaultLocale.getLanguage());
            }
            if (currentInfo == null && (currentInfo = getLanguageFromDict(getLocaleString(this.systemDefaultLocale))) == null) {
                currentInfo = getLanguageFromDict("en");
            }
            applyLanguage(currentInfo, override, true, UserConfig.selectedAccount);
        } catch (Exception e) {
            FileLog.e(e);
        }
        try {
            IntentFilter timezoneFilter = new IntentFilter("android.intent.action.TIMEZONE_CHANGED");
            ApplicationLoader.applicationContext.registerReceiver(new TimeZoneChangedReceiver(), timezoneFilter);
        } catch (Exception e2) {
            FileLog.e(e2);
        }
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$LocaleController$oDIpluViJOlSFNxWTuurUUxtPSg
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$new$1$LocaleController();
            }
        });
    }

    public /* synthetic */ void lambda$new$0$LocaleController() {
        loadRemoteLanguages(UserConfig.selectedAccount);
    }

    public /* synthetic */ void lambda$new$1$LocaleController() {
        this.currentSystemLocale = getSystemLocaleStringIso639();
    }

    public LocaleInfo getLanguageFromDict(String key) {
        if (key == null) {
            return null;
        }
        return this.languagesDict.get(key.toLowerCase().replace("-", "_"));
    }

    private void addRules(String[] languages, PluralRules rules) {
        for (String language : languages) {
            this.allRules.put(language, rules);
        }
    }

    private String stringForQuantity(int quantity) {
        if (quantity == 1) {
            return "zero";
        }
        if (quantity == 2) {
            return "one";
        }
        if (quantity == 4) {
            return "two";
        }
        if (quantity == 8) {
            return "few";
        }
        if (quantity == 16) {
            return "many";
        }
        return "other";
    }

    public Locale getSystemDefaultLocale() {
        return this.systemDefaultLocale;
    }

    public boolean isCurrentLocalLocale() {
        return this.currentLocaleInfo.isLocal();
    }

    public String getCurrentLanguage() {
        return this.currentLocaleInfo.shortName;
    }

    public void reloadCurrentRemoteLocale(int currentAccount, String langCode) {
        if (langCode != null) {
            langCode = langCode.replace("-", "_");
        }
        if (langCode != null) {
            LocaleInfo localeInfo = this.currentLocaleInfo;
            if (localeInfo == null) {
                return;
            }
            if (!langCode.equals(localeInfo.shortName) && !langCode.equals(this.currentLocaleInfo.baseLangCode)) {
                return;
            }
        }
        applyRemoteLanguage(this.currentLocaleInfo, langCode, true, currentAccount);
    }

    public void checkUpdateForCurrentRemoteLocale(int currentAccount, int version, int baseVersion) {
        LocaleInfo localeInfo = this.currentLocaleInfo;
        if (localeInfo != null) {
            if (localeInfo != null && !localeInfo.isRemote() && !this.currentLocaleInfo.isUnofficial()) {
                return;
            }
            if (this.currentLocaleInfo.hasBaseLang() && this.currentLocaleInfo.baseVersion < baseVersion) {
                LocaleInfo localeInfo2 = this.currentLocaleInfo;
                applyRemoteLanguage(localeInfo2, localeInfo2.baseLangCode, false, currentAccount);
            }
            if (this.currentLocaleInfo.version < version) {
                LocaleInfo localeInfo3 = this.currentLocaleInfo;
                applyRemoteLanguage(localeInfo3, localeInfo3.shortName, false, currentAccount);
            }
        }
    }

    private String getLocaleString(Locale locale) {
        if (locale == null) {
            return "en";
        }
        String languageCode = locale.getLanguage();
        String countryCode = locale.getCountry();
        String variantCode = locale.getVariant();
        if (languageCode.length() == 0 && countryCode.length() == 0) {
            return "en";
        }
        StringBuilder result = new StringBuilder(11);
        result.append(languageCode);
        if (countryCode.length() > 0 || variantCode.length() > 0) {
            result.append('_');
        }
        result.append(countryCode);
        if (variantCode.length() > 0) {
            result.append('_');
        }
        result.append(variantCode);
        return result.toString();
    }

    public static String getSystemLocaleStringIso639() {
        Locale locale = getInstance().getSystemDefaultLocale();
        if (locale == null) {
            return "en";
        }
        String languageCode = locale.getLanguage();
        String countryCode = locale.getCountry();
        String variantCode = locale.getVariant();
        if (languageCode.length() == 0 && countryCode.length() == 0) {
            return "en";
        }
        StringBuilder result = new StringBuilder(11);
        result.append(languageCode);
        if (countryCode.length() > 0 || variantCode.length() > 0) {
            result.append('-');
        }
        result.append(countryCode);
        if (variantCode.length() > 0) {
            result.append('_');
        }
        result.append(variantCode);
        return result.toString();
    }

    public static String getLocaleStringIso639() {
        LocaleInfo info = getInstance().currentLocaleInfo;
        if (info != null) {
            return info.getLangCode();
        }
        Locale locale = getInstance().currentLocale;
        if (locale == null) {
            return "en";
        }
        String languageCode = locale.getLanguage();
        String countryCode = locale.getCountry();
        String variantCode = locale.getVariant();
        if (languageCode.length() == 0 && countryCode.length() == 0) {
            return "en";
        }
        StringBuilder result = new StringBuilder(11);
        result.append(languageCode);
        if (countryCode.length() > 0 || variantCode.length() > 0) {
            result.append('-');
        }
        result.append(countryCode);
        if (variantCode.length() > 0) {
            result.append('_');
        }
        result.append(variantCode);
        return result.toString();
    }

    /* JADX WARN: Removed duplicated region for block: B:66:0x00ba  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static java.lang.String getLocaleAlias(java.lang.String r16) {
        /*
            Method dump skipped, instruction units count: 232
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.messenger.LocaleController.getLocaleAlias(java.lang.String):java.lang.String");
    }

    public boolean applyLanguageFile(File file, int currentAccount) {
        HashMap<String, String> stringMap;
        String languageName;
        String languageNameInEnglish;
        String languageCode;
        LocaleInfo localeInfo;
        try {
            stringMap = getLocaleFileStrings(file);
            languageName = stringMap.get("LanguageName");
            languageNameInEnglish = stringMap.get("LanguageNameInEnglish");
            languageCode = stringMap.get("LanguageCode");
        } catch (Exception e) {
            e = e;
        }
        if (languageName != null && languageName.length() > 0 && languageNameInEnglish != null && languageNameInEnglish.length() > 0 && languageCode != null && languageCode.length() > 0 && !languageName.contains("&") && !languageName.contains(LogUtils.VERTICAL) && !languageNameInEnglish.contains("&") && !languageNameInEnglish.contains(LogUtils.VERTICAL)) {
            if (languageCode.contains("&") || languageCode.contains(LogUtils.VERTICAL) || languageCode.contains("/") || languageCode.contains("\\")) {
                return false;
            }
            File finalFile = new File(ApplicationLoader.getFilesDirFixed(), languageCode + ".xml");
            try {
                if (!AndroidUtilities.copyFile(file, finalFile)) {
                    return false;
                }
                String key = "local_" + languageCode.toLowerCase();
                LocaleInfo localeInfo2 = getLanguageFromDict(key);
                if (localeInfo2 != null) {
                    localeInfo = localeInfo2;
                } else {
                    LocaleInfo localeInfo3 = new LocaleInfo();
                    localeInfo3.name = languageName;
                    localeInfo3.nameEnglish = languageNameInEnglish;
                    localeInfo3.shortName = languageCode.toLowerCase();
                    localeInfo3.pluralLangCode = localeInfo3.shortName;
                    localeInfo3.pathToFile = finalFile.getAbsolutePath();
                    this.languages.add(localeInfo3);
                    this.languagesDict.put(localeInfo3.getKey(), localeInfo3);
                    this.otherLanguages.add(localeInfo3);
                    saveOtherLanguages();
                    localeInfo = localeInfo3;
                }
                this.localeValues = stringMap;
                applyLanguage(localeInfo, true, false, true, false, currentAccount);
                return true;
            } catch (Exception e2) {
                e = e2;
            }
            FileLog.e(e);
            return false;
        }
        return false;
    }

    private void saveOtherLanguages() {
        SharedPreferences preferences = ApplicationLoader.applicationContext.getSharedPreferences("langconfig", 0);
        SharedPreferences.Editor editor = preferences.edit();
        StringBuilder stringBuilder = new StringBuilder();
        for (int a = 0; a < this.otherLanguages.size(); a++) {
            LocaleInfo localeInfo = this.otherLanguages.get(a);
            String loc = localeInfo.getSaveString();
            if (loc != null) {
                if (stringBuilder.length() != 0) {
                    stringBuilder.append("&");
                }
                stringBuilder.append(loc);
            }
        }
        editor.putString("locales", stringBuilder.toString());
        stringBuilder.setLength(0);
        for (int a2 = 0; a2 < this.remoteLanguages.size(); a2++) {
            LocaleInfo localeInfo2 = this.remoteLanguages.get(a2);
            String loc2 = localeInfo2.getSaveString();
            if (loc2 != null) {
                if (stringBuilder.length() != 0) {
                    stringBuilder.append("&");
                }
                stringBuilder.append(loc2);
            }
        }
        editor.putString("remote", stringBuilder.toString());
        stringBuilder.setLength(0);
        for (int a3 = 0; a3 < this.unofficialLanguages.size(); a3++) {
            LocaleInfo localeInfo3 = this.unofficialLanguages.get(a3);
            String loc3 = localeInfo3.getSaveString();
            if (loc3 != null) {
                if (stringBuilder.length() != 0) {
                    stringBuilder.append("&");
                }
                stringBuilder.append(loc3);
            }
        }
        editor.putString("unofficial", stringBuilder.toString());
        editor.commit();
    }

    public boolean deleteLanguage(LocaleInfo localeInfo, int currentAccount) {
        if (localeInfo.pathToFile == null || (localeInfo.isRemote() && localeInfo.serverIndex != Integer.MAX_VALUE)) {
            return false;
        }
        if (this.currentLocaleInfo == localeInfo) {
            LocaleInfo info = null;
            if (this.systemDefaultLocale.getLanguage() != null) {
                info = getLanguageFromDict(this.systemDefaultLocale.getLanguage());
            }
            if (info == null) {
                info = getLanguageFromDict(getLocaleString(this.systemDefaultLocale));
            }
            if (info == null) {
                info = getLanguageFromDict("en");
            }
            applyLanguage(info, true, false, currentAccount);
        }
        this.unofficialLanguages.remove(localeInfo);
        this.remoteLanguages.remove(localeInfo);
        this.remoteLanguagesDict.remove(localeInfo.getKey());
        this.otherLanguages.remove(localeInfo);
        this.languages.remove(localeInfo);
        this.languagesDict.remove(localeInfo.getKey());
        File file = new File(localeInfo.pathToFile);
        file.delete();
        saveOtherLanguages();
        return true;
    }

    private void loadOtherLanguages() {
        SharedPreferences preferences = ApplicationLoader.applicationContext.getSharedPreferences("langconfig", 0);
        String locales = preferences.getString("locales", null);
        if (!TextUtils.isEmpty(locales)) {
            String[] localesArr = locales.split("&");
            for (String locale : localesArr) {
                LocaleInfo localeInfo = LocaleInfo.createWithString(locale);
                if (localeInfo != null) {
                    this.otherLanguages.add(localeInfo);
                }
            }
        }
        String locales2 = preferences.getString("remote", null);
        if (!TextUtils.isEmpty(locales2)) {
            String[] localesArr2 = locales2.split("&");
            for (String locale2 : localesArr2) {
                LocaleInfo localeInfo2 = LocaleInfo.createWithString(locale2);
                localeInfo2.shortName = localeInfo2.shortName.replace("-", "_");
                if (!this.remoteLanguagesDict.containsKey(localeInfo2.getKey()) && localeInfo2 != null) {
                    this.remoteLanguages.add(localeInfo2);
                    this.remoteLanguagesDict.put(localeInfo2.getKey(), localeInfo2);
                }
            }
        }
        String locales3 = preferences.getString("unofficial", null);
        if (!TextUtils.isEmpty(locales3)) {
            String[] localesArr3 = locales3.split("&");
            for (String locale3 : localesArr3) {
                LocaleInfo localeInfo3 = LocaleInfo.createWithString(locale3);
                localeInfo3.shortName = localeInfo3.shortName.replace("-", "_");
                if (localeInfo3 != null) {
                    this.unofficialLanguages.add(localeInfo3);
                }
            }
        }
    }

    private HashMap<String, String> getLocaleFileStrings(File file) {
        return getLocaleFileStrings(file, false);
    }

    private HashMap<String, String> getLocaleFileStrings(File file, boolean preserveEscapes) throws XmlPullParserException, IOException {
        FileInputStream stream = null;
        this.reloadLastFile = false;
        try {
            try {
                if (!file.exists()) {
                    HashMap<String, String> map = new HashMap<>();
                    if (0 != 0) {
                        try {
                            stream.close();
                        } catch (Exception e) {
                            FileLog.e(e);
                        }
                    }
                    return map;
                }
                HashMap<String, String> stringMap = new HashMap<>();
                XmlPullParser parser = Xml.newPullParser();
                FileInputStream stream2 = new FileInputStream(file);
                parser.setInput(stream2, "UTF-8");
                String name = null;
                String value = null;
                String attrName = null;
                for (int eventType = parser.getEventType(); eventType != 1; eventType = parser.next()) {
                    if (eventType == 2) {
                        name = parser.getName();
                        int c = parser.getAttributeCount();
                        if (c > 0) {
                            attrName = parser.getAttributeValue(0);
                        }
                    } else if (eventType == 4) {
                        if (attrName != null && (value = parser.getText()) != null) {
                            String value2 = value.trim();
                            if (preserveEscapes) {
                                value = value2.replace("<", "&lt;").replace(">", "&gt;").replace("'", "\\'").replace("& ", "&amp; ");
                            } else {
                                String old = value2.replace("\\n", ShellAdbUtils.COMMAND_LINE_END).replace("\\", "");
                                value = old.replace("&lt;", "<");
                                if (!this.reloadLastFile && !value.equals(old)) {
                                    this.reloadLastFile = true;
                                }
                            }
                        }
                    } else if (eventType == 3) {
                        value = null;
                        attrName = null;
                        name = null;
                    }
                    if (name != null && name.equals("string") && value != null && attrName != null && value.length() != 0 && attrName.length() != 0) {
                        stringMap.put(attrName, value);
                        name = null;
                        value = null;
                        attrName = null;
                    }
                }
                try {
                    stream2.close();
                } catch (Exception e2) {
                    FileLog.e(e2);
                }
                return stringMap;
            } catch (Throwable th) {
                if (0 != 0) {
                    try {
                        stream.close();
                    } catch (Exception e3) {
                        FileLog.e(e3);
                    }
                }
                throw th;
            }
        } catch (Exception e4) {
            FileLog.e(e4);
            this.reloadLastFile = true;
            if (0 != 0) {
                try {
                    stream.close();
                } catch (Exception e5) {
                    FileLog.e(e5);
                }
            }
            return new HashMap<>();
        }
    }

    public void applyLanguage(LocaleInfo localeInfo, boolean override, boolean init, int currentAccount) {
        applyLanguage(localeInfo, override, init, false, false, currentAccount);
    }

    public void applyLanguage(final LocaleInfo localeInfo, boolean override, boolean init, boolean fromFile, boolean force, final int currentAccount) {
        String[] args;
        Locale newLocale;
        if (localeInfo == null) {
            return;
        }
        boolean hasBase = localeInfo.hasBaseLang();
        File pathToFile = localeInfo.getPathToFile();
        File pathToBaseFile = localeInfo.getPathToBaseFile();
        String str = localeInfo.shortName;
        if (!init) {
            ConnectionsManager.setLangCode(localeInfo.getLangCode());
        }
        LocaleInfo existingInfo = getLanguageFromDict(localeInfo.getKey());
        if (existingInfo == null) {
            if (localeInfo.isRemote()) {
                this.remoteLanguages.add(localeInfo);
                this.remoteLanguagesDict.put(localeInfo.getKey(), localeInfo);
                this.languages.add(localeInfo);
                this.languagesDict.put(localeInfo.getKey(), localeInfo);
                saveOtherLanguages();
            } else if (localeInfo.isUnofficial()) {
                this.unofficialLanguages.add(localeInfo);
                this.languagesDict.put(localeInfo.getKey(), localeInfo);
                saveOtherLanguages();
            }
        }
        if ((localeInfo.isRemote() || localeInfo.isUnofficial()) && (force || !pathToFile.exists() || (hasBase && !pathToBaseFile.exists()))) {
            if (BuildVars.LOGS_ENABLED) {
                FileLog.d("reload locale because one of file doesn't exist" + pathToFile + " " + pathToBaseFile);
            }
            if (init) {
                AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$LocaleController$QCb_hD-2wwa4rgqqS_0mxCiX4pU
                    @Override // java.lang.Runnable
                    public final void run() {
                        this.f$0.lambda$applyLanguage$2$LocaleController(localeInfo, currentAccount);
                    }
                });
            } else {
                applyRemoteLanguage(localeInfo, null, true, currentAccount);
            }
        }
        try {
            if (!TextUtils.isEmpty(localeInfo.pluralLangCode)) {
                args = localeInfo.pluralLangCode.split("_");
            } else if (!TextUtils.isEmpty(localeInfo.baseLangCode)) {
                args = localeInfo.baseLangCode.split("_");
            } else {
                args = localeInfo.shortName.split("_");
            }
            if (args.length == 1) {
                newLocale = new Locale(args[0]);
            } else {
                newLocale = new Locale(args[0], args[1]);
            }
            if (override) {
                this.languageOverride = localeInfo.shortName;
                SharedPreferences preferences = MessagesController.getGlobalMainSettings();
                SharedPreferences.Editor editor = preferences.edit();
                editor.putString("language", localeInfo.getKey());
                editor.commit();
            }
            if (pathToFile == null) {
                this.localeValues.clear();
            } else if (!fromFile) {
                HashMap<String, String> localeFileStrings = getLocaleFileStrings(hasBase ? localeInfo.getPathToBaseFile() : localeInfo.getPathToFile());
                this.localeValues = localeFileStrings;
                if (hasBase) {
                    localeFileStrings.putAll(getLocaleFileStrings(localeInfo.getPathToFile()));
                }
            }
            this.currentLocale = newLocale;
            this.currentLocaleInfo = localeInfo;
            if (localeInfo != null && !TextUtils.isEmpty(localeInfo.pluralLangCode)) {
                this.currentPluralRules = this.allRules.get(this.currentLocaleInfo.pluralLangCode);
            }
            if (this.currentPluralRules == null) {
                PluralRules pluralRules = this.allRules.get(args[0]);
                this.currentPluralRules = pluralRules;
                if (pluralRules == null) {
                    PluralRules pluralRules2 = this.allRules.get(this.currentLocale.getLanguage());
                    this.currentPluralRules = pluralRules2;
                    if (pluralRules2 == null) {
                        this.currentPluralRules = new PluralRules_None();
                    }
                }
            }
            this.changingConfiguration = true;
            Locale.setDefault(this.currentLocale);
            Configuration config = new Configuration();
            config.locale = this.currentLocale;
            ApplicationLoader.applicationContext.getResources().updateConfiguration(config, ApplicationLoader.applicationContext.getResources().getDisplayMetrics());
            this.changingConfiguration = false;
            if (this.reloadLastFile) {
                if (init) {
                    AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$LocaleController$eTz8wkDNwVzVXi7kVtvR166acDs
                        @Override // java.lang.Runnable
                        public final void run() {
                            this.f$0.lambda$applyLanguage$3$LocaleController(currentAccount);
                        }
                    });
                } else {
                    reloadCurrentRemoteLocale(currentAccount, null);
                }
                this.reloadLastFile = false;
            }
        } catch (Exception e) {
            FileLog.e(e);
            this.changingConfiguration = false;
        }
        recreateFormatters();
    }

    public /* synthetic */ void lambda$applyLanguage$2$LocaleController(LocaleInfo localeInfo, int currentAccount) {
        applyRemoteLanguage(localeInfo, null, true, currentAccount);
    }

    public /* synthetic */ void lambda$applyLanguage$3$LocaleController(int currentAccount) {
        reloadCurrentRemoteLocale(currentAccount, null);
    }

    public LocaleInfo getCurrentLocaleInfo() {
        return this.currentLocaleInfo;
    }

    public static String getCurrentLanguageName() {
        LocaleInfo localeInfo = getInstance().currentLocaleInfo;
        return (localeInfo == null || TextUtils.isEmpty(localeInfo.name)) ? getString("LanguageName", mpEIGo.juqQQs.esbSDO.R.string.LanguageName) : localeInfo.name;
    }

    private String getStringInternal(String key, int res) {
        String value = BuildVars.USE_CLOUD_STRINGS ? this.localeValues.get(key) : null;
        if (value == null) {
            try {
                value = ApplicationLoader.applicationContext.getString(res);
            } catch (Exception e) {
                FileLog.e(e);
            }
        }
        if (value == null) {
            return "LOC_ERR:" + key;
        }
        return value;
    }

    public static String getServerString(String key) {
        int resourceId;
        String value = getInstance().localeValues.get(key);
        if (value == null && (resourceId = ApplicationLoader.applicationContext.getResources().getIdentifier(key, "string", ApplicationLoader.applicationContext.getPackageName())) != 0) {
            return ApplicationLoader.applicationContext.getString(resourceId);
        }
        return value;
    }

    public static String getString(int res) {
        return getString(res + "", res);
    }

    public static String getString(String key, int res) {
        return getInstance().getStringInternal(key, res);
    }

    public static String getPluralString(String key, int plural) {
        if (key == null || key.length() == 0 || getInstance().currentPluralRules == null) {
            return "LOC_ERR:" + key;
        }
        String param = key + "_" + getInstance().stringForQuantity(getInstance().currentPluralRules.quantityForNumber(plural));
        int resourceId = ApplicationLoader.applicationContext.getResources().getIdentifier(param, "string", ApplicationLoader.applicationContext.getPackageName());
        return getString(param, resourceId);
    }

    public static String formatPluralString(String key, int plural) {
        if (key == null || key.length() == 0 || getInstance().currentPluralRules == null) {
            return "LOC_ERR:" + key;
        }
        String param = key + "_" + getInstance().stringForQuantity(getInstance().currentPluralRules.quantityForNumber(plural));
        int resourceId = ApplicationLoader.applicationContext.getResources().getIdentifier(param, "string", ApplicationLoader.applicationContext.getPackageName());
        return formatString(param, resourceId, Integer.valueOf(plural));
    }

    public static String formatString(String key, int res, Object... args) {
        try {
            String value = BuildVars.USE_CLOUD_STRINGS ? getInstance().localeValues.get(key) : null;
            if (value == null) {
                value = ApplicationLoader.applicationContext.getString(res);
            }
            if (getInstance().currentLocale != null) {
                return String.format(getInstance().currentLocale, value, args);
            }
            return String.format(value, args);
        } catch (Exception e) {
            FileLog.e(e);
            return "LOC_ERR: " + key;
        }
    }

    public static String formatTTLString(int ttl) {
        if (ttl < 60) {
            return formatPluralString("Seconds", ttl);
        }
        if (ttl < 3600) {
            return formatPluralString("Minutes", ttl / 60);
        }
        if (ttl < 86400) {
            return formatPluralString("Hours", (ttl / 60) / 60);
        }
        if (ttl < 604800) {
            return formatPluralString("Days", ((ttl / 60) / 60) / 24);
        }
        int days = ((ttl / 60) / 60) / 24;
        return ttl % 7 == 0 ? formatPluralString("Weeks", days / 7) : String.format("%s %s", formatPluralString("Weeks", days / 7), formatPluralString("Days", days % 7));
    }

    /* JADX WARN: Failed to restore switch over string. Please report as a decompilation issue */
    public String formatCurrencyString(long amount, String type) {
        String customFormat;
        double doubleAmount;
        String type2 = type.toUpperCase();
        boolean discount = amount < 0;
        long amount2 = Math.abs(amount);
        Currency currency = Currency.getInstance(type2);
        byte b = -1;
        switch (type2.hashCode()) {
            case 65726:
                if (type2.equals("BHD")) {
                    b = 2;
                }
                break;
            case 65759:
                if (type2.equals("BIF")) {
                    b = 9;
                }
                break;
            case 66267:
                if (type2.equals("BYR")) {
                    b = 10;
                }
                break;
            case 66813:
                if (type2.equals("CLF")) {
                    b = 0;
                }
                break;
            case 66823:
                if (type2.equals("CLP")) {
                    b = 11;
                }
                break;
            case 67122:
                if (type2.equals("CVE")) {
                    b = 12;
                }
                break;
            case 67712:
                if (type2.equals("DJF")) {
                    b = 13;
                }
                break;
            case 70719:
                if (type2.equals("GNF")) {
                    b = 14;
                }
                break;
            case 72732:
                if (type2.equals("IQD")) {
                    b = 3;
                }
                break;
            case 72777:
                if (type2.equals("IRR")) {
                    b = 1;
                }
                break;
            case 72801:
                if (type2.equals("ISK")) {
                    b = 15;
                }
                break;
            case 73631:
                if (type2.equals("JOD")) {
                    b = 4;
                }
                break;
            case 73683:
                if (type2.equals("JPY")) {
                    b = 16;
                }
                break;
            case 74532:
                if (type2.equals("KMF")) {
                    b = 17;
                }
                break;
            case 74704:
                if (type2.equals("KRW")) {
                    b = 18;
                }
                break;
            case 74840:
                if (type2.equals("KWD")) {
                    b = 5;
                }
                break;
            case 75863:
                if (type2.equals("LYD")) {
                    b = 6;
                }
                break;
            case 76263:
                if (type2.equals("MGA")) {
                    b = 19;
                }
                break;
            case 76618:
                if (type2.equals("MRO")) {
                    b = 29;
                }
                break;
            case 78388:
                if (type2.equals("OMR")) {
                    b = 7;
                }
                break;
            case 79710:
                if (type2.equals("PYG")) {
                    b = 20;
                }
                break;
            case 81569:
                if (type2.equals("RWF")) {
                    b = 21;
                }
                break;
            case 83210:
                if (type2.equals("TND")) {
                    b = 8;
                }
                break;
            case 83974:
                if (type2.equals("UGX")) {
                    b = 22;
                }
                break;
            case 84517:
                if (type2.equals("UYI")) {
                    b = 23;
                }
                break;
            case 85132:
                if (type2.equals("VND")) {
                    b = 24;
                }
                break;
            case 85367:
                if (type2.equals("VUV")) {
                    b = 25;
                }
                break;
            case 86653:
                if (type2.equals("XAF")) {
                    b = JSONLexer.EOI;
                }
                break;
            case 87087:
                if (type2.equals("XOF")) {
                    b = 27;
                }
                break;
            case 87118:
                if (type2.equals("XPF")) {
                    b = 28;
                }
                break;
        }
        switch (b) {
            case 0:
                customFormat = " %.4f";
                doubleAmount = amount2 / 10000.0d;
                break;
            case 1:
                doubleAmount = amount2 / 100.0f;
                if (amount2 % 100 == 0) {
                    customFormat = " %.0f";
                } else {
                    customFormat = " %.2f";
                }
                break;
            case 2:
            case 3:
            case 4:
            case 5:
            case 6:
            case 7:
            case 8:
                customFormat = " %.3f";
                doubleAmount = amount2 / 1000.0d;
                break;
            case 9:
            case 10:
            case 11:
            case 12:
            case 13:
            case 14:
            case 15:
            case 16:
            case 17:
            case 18:
            case 19:
            case 20:
            case 21:
            case 22:
            case 23:
            case 24:
            case 25:
            case 26:
            case 27:
            case 28:
                customFormat = " %.0f";
                doubleAmount = amount2;
                break;
            case 29:
                customFormat = " %.1f";
                doubleAmount = amount2 / 10.0d;
                break;
            default:
                customFormat = " %.2f";
                doubleAmount = amount2 / 100.0d;
                break;
        }
        if (currency != null) {
            Locale locale = this.currentLocale;
            if (locale == null) {
                locale = this.systemDefaultLocale;
            }
            NumberFormat format = NumberFormat.getCurrencyInstance(locale);
            format.setCurrency(currency);
            if (type2.equals("IRR")) {
                format.setMaximumFractionDigits(0);
            }
            StringBuilder sb = new StringBuilder();
            sb.append(discount ? "-" : "");
            sb.append(format.format(doubleAmount));
            return sb.toString();
        }
        StringBuilder sb2 = new StringBuilder();
        sb2.append(discount ? "-" : "");
        sb2.append(String.format(Locale.US, type2 + customFormat, Double.valueOf(doubleAmount)));
        return sb2.toString();
    }

    /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
    /* JADX WARN: Failed to restore switch over string. Please report as a decompilation issue */
    /* JADX WARN: Removed duplicated region for block: B:95:0x0169  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.String formatCurrencyDecimalString(long r10, java.lang.String r12, boolean r13) {
        /*
            Method dump skipped, instruction units count: 650
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.messenger.LocaleController.formatCurrencyDecimalString(long, java.lang.String, boolean):java.lang.String");
    }

    public static String formatStringSimple(String string, Object... args) {
        try {
            if (getInstance().currentLocale != null) {
                return String.format(getInstance().currentLocale, string, args);
            }
            return String.format(string, args);
        } catch (Exception e) {
            FileLog.e(e);
            return "LOC_ERR: " + string;
        }
    }

    public static String formatCallDuration(int duration) {
        if (duration > 3600) {
            String result = formatPluralString("Hours", duration / 3600);
            int minutes = (duration % 3600) / 60;
            if (minutes > 0) {
                return result + ", " + formatPluralString("Minutes", minutes);
            }
            return result;
        }
        if (duration > 60) {
            return formatPluralString("Minutes", duration / 60);
        }
        return formatPluralString("Seconds", duration);
    }

    public void onDeviceConfigurationChange(Configuration newConfig) {
        if (this.changingConfiguration) {
            return;
        }
        is24HourFormat = DateFormat.is24HourFormat(ApplicationLoader.applicationContext);
        this.systemDefaultLocale = newConfig.locale;
        if (this.languageOverride != null) {
            LocaleInfo toSet = this.currentLocaleInfo;
            this.currentLocaleInfo = null;
            applyLanguage(toSet, false, false, UserConfig.selectedAccount);
        } else {
            Locale newLocale = newConfig.locale;
            if (newLocale != null) {
                String d1 = newLocale.getDisplayName();
                String d2 = this.currentLocale.getDisplayName();
                if (d1 != null && d2 != null && !d1.equals(d2)) {
                    recreateFormatters();
                }
                this.currentLocale = newLocale;
                LocaleInfo localeInfo = this.currentLocaleInfo;
                if (localeInfo != null && !TextUtils.isEmpty(localeInfo.pluralLangCode)) {
                    this.currentPluralRules = this.allRules.get(this.currentLocaleInfo.pluralLangCode);
                }
                if (this.currentPluralRules == null) {
                    PluralRules pluralRules = this.allRules.get(this.currentLocale.getLanguage());
                    this.currentPluralRules = pluralRules;
                    if (pluralRules == null) {
                        this.currentPluralRules = this.allRules.get("en");
                    }
                }
            }
        }
        String newSystemLocale = getSystemLocaleStringIso639();
        String str = this.currentSystemLocale;
        if (str != null && !newSystemLocale.equals(str)) {
            this.currentSystemLocale = newSystemLocale;
            ConnectionsManager.setSystemLangCode(newSystemLocale);
        }
    }

    public static String formatDateChat(long date) {
        return formatDateChat(date, false);
    }

    public static String formatDateChat(long date, boolean checkYear) {
        try {
            Calendar calendar = Calendar.getInstance();
            calendar.setTimeInMillis(System.currentTimeMillis());
            int currentYear = calendar.get(1);
            long date2 = date * 1000;
            calendar.setTimeInMillis(date2);
            if ((checkYear && currentYear == calendar.get(1)) || (!checkYear && Math.abs(System.currentTimeMillis() - date2) < 31536000000L)) {
                return getInstance().chatDate.format(date2);
            }
            return getInstance().chatFullDate.format(date2);
        } catch (Exception e) {
            FileLog.e(e);
            return "LOC_ERR: formatDateChat";
        }
    }

    public static String formatDate(long date) {
        long date2 = date * 1000;
        try {
            Calendar rightNow = Calendar.getInstance();
            int day = rightNow.get(6);
            int year = rightNow.get(1);
            rightNow.setTimeInMillis(date2);
            int dateDay = rightNow.get(6);
            int dateYear = rightNow.get(1);
            if (dateDay == day && year == dateYear) {
                return getInstance().formatterDay.format(new Date(date2));
            }
            if (dateDay + 1 == day && year == dateYear) {
                return getString("Yesterday", mpEIGo.juqQQs.esbSDO.R.string.Yesterday);
            }
            if (Math.abs(System.currentTimeMillis() - date2) < 31536000000L) {
                return getInstance().formatterDayMonth.format(new Date(date2));
            }
            return getInstance().formatterYear.format(new Date(date2));
        } catch (Exception e) {
            FileLog.e(e);
            return "LOC_ERR: formatDate";
        }
    }

    public static String formatDateAudio(long date) {
        long date2 = date * 1000;
        try {
            Calendar rightNow = Calendar.getInstance();
            int day = rightNow.get(6);
            int year = rightNow.get(1);
            rightNow.setTimeInMillis(date2);
            int dateDay = rightNow.get(6);
            int dateYear = rightNow.get(1);
            if (dateDay == day && year == dateYear) {
                return formatString("TodayAtFormatted", mpEIGo.juqQQs.esbSDO.R.string.TodayAtFormatted, getInstance().formatterDay.format(new Date(date2)));
            }
            if (dateDay + 1 == day && year == dateYear) {
                return formatString("YesterdayAtFormatted", mpEIGo.juqQQs.esbSDO.R.string.YesterdayAtFormatted, getInstance().formatterDay.format(new Date(date2)));
            }
            return Math.abs(System.currentTimeMillis() - date2) < 31536000000L ? formatString("formatDateAtTime", mpEIGo.juqQQs.esbSDO.R.string.formatDateAtTime, getInstance().formatterDayMonth.format(new Date(date2)), getInstance().formatterDay.format(new Date(date2))) : formatString("formatDateAtTime", mpEIGo.juqQQs.esbSDO.R.string.formatDateAtTime, getInstance().formatterYear.format(new Date(date2)), getInstance().formatterDay.format(new Date(date2)));
        } catch (Exception e) {
            FileLog.e(e);
            return "LOC_ERR";
        }
    }

    public static String formatDateCallLog(long date) {
        long date2 = date * 1000;
        try {
            Calendar rightNow = Calendar.getInstance();
            int day = rightNow.get(6);
            int year = rightNow.get(1);
            rightNow.setTimeInMillis(date2);
            int dateDay = rightNow.get(6);
            int dateYear = rightNow.get(1);
            if (dateDay == day && year == dateYear) {
                return getInstance().formatterDay.format(new Date(date2));
            }
            if (dateDay + 1 == day && year == dateYear) {
                return formatString("YesterdayAtFormatted", mpEIGo.juqQQs.esbSDO.R.string.YesterdayAtFormatted, getInstance().formatterDay.format(new Date(date2)));
            }
            return Math.abs(System.currentTimeMillis() - date2) < 31536000000L ? formatString("formatDateAtTime", mpEIGo.juqQQs.esbSDO.R.string.formatDateAtTime, getInstance().chatDate.format(new Date(date2)), getInstance().formatterDay.format(new Date(date2))) : formatString("formatDateAtTime", mpEIGo.juqQQs.esbSDO.R.string.formatDateAtTime, getInstance().chatFullDate.format(new Date(date2)), getInstance().formatterDay.format(new Date(date2)));
        } catch (Exception e) {
            FileLog.e(e);
            return "LOC_ERR";
        }
    }

    public static String formatLocationUpdateDate(long date) {
        long date2 = date * 1000;
        try {
            Calendar rightNow = Calendar.getInstance();
            int day = rightNow.get(6);
            int year = rightNow.get(1);
            rightNow.setTimeInMillis(date2);
            int dateDay = rightNow.get(6);
            int dateYear = rightNow.get(1);
            if (dateDay == day && year == dateYear) {
                int diff = ((int) (((long) ConnectionsManager.getInstance(UserConfig.selectedAccount).getCurrentTime()) - (date2 / 1000))) / 60;
                if (diff < 1) {
                    return getString("LocationUpdatedJustNow", mpEIGo.juqQQs.esbSDO.R.string.LocationUpdatedJustNow);
                }
                if (diff >= 60) {
                    return formatString("LocationUpdatedFormatted", mpEIGo.juqQQs.esbSDO.R.string.LocationUpdatedFormatted, formatString("TodayAtFormatted", mpEIGo.juqQQs.esbSDO.R.string.TodayAtFormatted, getInstance().formatterDay.format(new Date(date2))));
                }
                return formatPluralString("UpdatedMinutes", diff);
            }
            if (dateDay + 1 == day && year == dateYear) {
                return formatString("LocationUpdatedFormatted", mpEIGo.juqQQs.esbSDO.R.string.LocationUpdatedFormatted, formatString("YesterdayAtFormatted", mpEIGo.juqQQs.esbSDO.R.string.YesterdayAtFormatted, getInstance().formatterDay.format(new Date(date2))));
            }
            if (Math.abs(System.currentTimeMillis() - date2) < 31536000000L) {
                String format = formatString("formatDateAtTime", mpEIGo.juqQQs.esbSDO.R.string.formatDateAtTime, getInstance().formatterDayMonth.format(new Date(date2)), getInstance().formatterDay.format(new Date(date2)));
                return formatString("LocationUpdatedFormatted", mpEIGo.juqQQs.esbSDO.R.string.LocationUpdatedFormatted, format);
            }
            String format2 = formatString("formatDateAtTime", mpEIGo.juqQQs.esbSDO.R.string.formatDateAtTime, getInstance().formatterYear.format(new Date(date2)), getInstance().formatterDay.format(new Date(date2)));
            return formatString("LocationUpdatedFormatted", mpEIGo.juqQQs.esbSDO.R.string.LocationUpdatedFormatted, format2);
        } catch (Exception e) {
            FileLog.e(e);
            return "LOC_ERR";
        }
    }

    public static String formatLocationLeftTime(int time) {
        int hours = (time / 60) / 60;
        int time2 = time - ((hours * 60) * 60);
        int minutes = time2 / 60;
        int time3 = time2 - (minutes * 60);
        if (hours != 0) {
            Object[] objArr = new Object[1];
            objArr[0] = Integer.valueOf((minutes <= 30 ? 0 : 1) + hours);
            String text = String.format("%dh", objArr);
            return text;
        }
        if (minutes == 0) {
            String text2 = String.format("%d", Integer.valueOf(time3));
            return text2;
        }
        Object[] objArr2 = new Object[1];
        objArr2[0] = Integer.valueOf((time3 <= 30 ? 0 : 1) + minutes);
        String text3 = String.format("%d", objArr2);
        return text3;
    }

    public static String formatDateOnline(long date) {
        long date2 = date * 1000;
        try {
            Calendar rightNow = Calendar.getInstance();
            int day = rightNow.get(6);
            int year = rightNow.get(1);
            rightNow.setTimeInMillis(date2);
            int dateDay = rightNow.get(6);
            int dateYear = rightNow.get(1);
            if (dateDay == day && year == dateYear) {
                return formatString("LastSeenFormatted", mpEIGo.juqQQs.esbSDO.R.string.LastSeenFormatted, formatString("TodayAtFormatted", mpEIGo.juqQQs.esbSDO.R.string.TodayAtFormatted, getInstance().formatterDay.format(new Date(date2))));
            }
            if (dateDay + 1 == day && year == dateYear) {
                return formatString("LastSeenFormatted", mpEIGo.juqQQs.esbSDO.R.string.LastSeenFormatted, formatString("YesterdayAtFormatted", mpEIGo.juqQQs.esbSDO.R.string.YesterdayAtFormatted, getInstance().formatterDay.format(new Date(date2))));
            }
            if (Math.abs(System.currentTimeMillis() - date2) < 31536000000L) {
                String format = formatString("formatDateAtTime", mpEIGo.juqQQs.esbSDO.R.string.formatDateAtTime, getInstance().formatterDayMonth.format(new Date(date2)), getInstance().formatterDay.format(new Date(date2)));
                return formatString("LastSeenDateFormatted", mpEIGo.juqQQs.esbSDO.R.string.LastSeenDateFormatted, format);
            }
            String format2 = formatString("formatDateAtTime", mpEIGo.juqQQs.esbSDO.R.string.formatDateAtTime, getInstance().formatterYear.format(new Date(date2)), getInstance().formatterDay.format(new Date(date2)));
            return formatString("LastSeenDateFormatted", mpEIGo.juqQQs.esbSDO.R.string.LastSeenDateFormatted, format2);
        } catch (Exception e) {
            FileLog.e(e);
            return "LOC_ERR";
        }
    }

    public static String formatDateOnlineNew(long date) {
        try {
            Calendar rightNow = Calendar.getInstance();
            int day = rightNow.get(6);
            int year = rightNow.get(1);
            rightNow.setTimeInMillis(date * 1000);
            int dateDay = rightNow.get(6);
            int dateYear = rightNow.get(1);
            if (dateDay == day && year == dateYear) {
                int diff = ((int) (((long) ConnectionsManager.getInstance(UserConfig.selectedAccount).getCurrentTime()) - date)) / 60;
                if (diff < 1) {
                    return getString("New_Online", mpEIGo.juqQQs.esbSDO.R.string.New_Online);
                }
                if (diff < 60) {
                    return formatString("LastSeenMins", mpEIGo.juqQQs.esbSDO.R.string.LastSeenMins, Integer.valueOf(diff));
                }
                return formatString("LastSeenHours", mpEIGo.juqQQs.esbSDO.R.string.LastSeenHours, Integer.valueOf((int) Math.ceil(diff / 60.0f)));
            }
            if (dateDay + 1 == day && year == dateYear) {
                return formatString("LastSeenDays", mpEIGo.juqQQs.esbSDO.R.string.LastSeenDays, 1);
            }
            long jCurrentTimeMillis = System.currentTimeMillis();
            Long.signum(date);
            if (Math.abs(jCurrentTimeMillis - (date * 1000)) < 31536000000L) {
                long dis = Math.abs(System.currentTimeMillis() - (1000 * date));
                if (dis < 2592000000L) {
                    int diff2 = (int) Math.ceil(dis / 8.64E7f);
                    return formatString("LastSeenDays", mpEIGo.juqQQs.esbSDO.R.string.LastSeenDays, Integer.valueOf(diff2));
                }
                int diff3 = (int) Math.ceil(dis / 2.592E9f);
                return formatString("LastSeenMonths", mpEIGo.juqQQs.esbSDO.R.string.LastSeenMonths, Integer.valueOf(diff3));
            }
            String format = formatString("formatDateAtTime", mpEIGo.juqQQs.esbSDO.R.string.formatDateAtTime, getInstance().formatterYear.format(new Date(date * 1000)), getInstance().formatterDay.format(new Date(1000 * date)));
            return formatString("LastSeenDateFormatted", mpEIGo.juqQQs.esbSDO.R.string.LastSeenDateFormatted, format);
        } catch (Exception e) {
            FileLog.e(e);
            return "LOC_ERR";
        }
    }

    private FastDateFormat createFormatter(Locale locale, String format, String defaultFormat) {
        if (format == null || format.length() == 0) {
            format = defaultFormat;
        }
        try {
            FastDateFormat formatter = FastDateFormat.getInstance(format, locale);
            return formatter;
        } catch (Exception e) {
            FastDateFormat formatter2 = FastDateFormat.getInstance(defaultFormat, locale);
            return formatter2;
        }
    }

    public void recreateFormatters() {
        int i;
        String str;
        int i2;
        String str2;
        int i3;
        String str3;
        Locale locale = this.currentLocale;
        if (locale == null) {
            locale = Locale.getDefault();
        }
        String lang = locale.getLanguage();
        if (lang == null) {
            lang = "en";
        }
        String lang2 = lang.toLowerCase();
        nameDisplayOrder = lang2.equals("ko") ? 2 : 1;
        this.formatterDayMonth = createFormatter(locale, getStringInternal("formatterMonth", mpEIGo.juqQQs.esbSDO.R.string.formatterMonth), "dd MMM");
        this.formatterYear = createFormatter(locale, getStringInternal("formatterYear", mpEIGo.juqQQs.esbSDO.R.string.formatterYear), "dd.MM.yy");
        this.formatterYearMax = createFormatter(locale, getStringInternal("formatterYearMax", mpEIGo.juqQQs.esbSDO.R.string.formatterYearMax), "dd.MM.yyyy");
        this.chatDate = createFormatter(locale, getStringInternal("chatDate", mpEIGo.juqQQs.esbSDO.R.string.chatDate), "d MMMM");
        this.chatFullDate = createFormatter(locale, getStringInternal("chatFullDate", mpEIGo.juqQQs.esbSDO.R.string.chatFullDate), "d MMMM yyyy");
        this.formatterWeek = createFormatter(locale, getStringInternal("formatterWeek", mpEIGo.juqQQs.esbSDO.R.string.formatterWeek), "EEE");
        this.formatterScheduleDay = createFormatter(locale, getStringInternal("formatDateSchedule", mpEIGo.juqQQs.esbSDO.R.string.formatDateSchedule), "MMM d");
        this.formatterScheduleYear = createFormatter(locale, getStringInternal("formatDateScheduleYear", mpEIGo.juqQQs.esbSDO.R.string.formatDateScheduleYear), "MMM d yyyy");
        this.formatterDay = createFormatter((lang2.toLowerCase().equals("ar") || lang2.toLowerCase().equals("ko")) ? locale : Locale.US, is24HourFormat ? getStringInternal("formatterDay24H", mpEIGo.juqQQs.esbSDO.R.string.formatterDay24H) : getStringInternal("formatterDay12H", mpEIGo.juqQQs.esbSDO.R.string.formatterDay12H), is24HourFormat ? "HH:mm" : "h:mm a");
        this.formatterDayNoly = createFormatter((lang2.toLowerCase().equals("ar") || lang2.toLowerCase().equals("ko")) ? locale : Locale.US, is24HourFormat ? getStringInternal("formatterDay24H", mpEIGo.juqQQs.esbSDO.R.string.formatterDay24H) : getStringInternal("formatterDay12H", mpEIGo.juqQQs.esbSDO.R.string.formatterDay12Honly), is24HourFormat ? "HH:mm" : "h:mm");
        if (is24HourFormat) {
            i = mpEIGo.juqQQs.esbSDO.R.string.formatterStats24H;
            str = "formatterStats24H";
        } else {
            i = mpEIGo.juqQQs.esbSDO.R.string.formatterStats12H;
            str = "formatterStats12H";
        }
        this.formatterStats = createFormatter(locale, getStringInternal(str, i), is24HourFormat ? "MMM dd yyyy, HH:mm" : "MMM dd yyyy, h:mm a");
        if (is24HourFormat) {
            i2 = mpEIGo.juqQQs.esbSDO.R.string.formatterBannedUntil24H;
            str2 = "formatterBannedUntil24H";
        } else {
            i2 = mpEIGo.juqQQs.esbSDO.R.string.formatterBannedUntil12H;
            str2 = "formatterBannedUntil12H";
        }
        this.formatterBannedUntil = createFormatter(locale, getStringInternal(str2, i2), is24HourFormat ? "MMM dd yyyy, HH:mm" : "MMM dd yyyy, h:mm a");
        if (is24HourFormat) {
            i3 = mpEIGo.juqQQs.esbSDO.R.string.formatterBannedUntilThisYear24H;
            str3 = "formatterBannedUntilThisYear24H";
        } else {
            i3 = mpEIGo.juqQQs.esbSDO.R.string.formatterBannedUntilThisYear12H;
            str3 = "formatterBannedUntilThisYear12H";
        }
        this.formatterBannedUntilThisYear = createFormatter(locale, getStringInternal(str3, i3), is24HourFormat ? "MMM dd, HH:mm" : "MMM dd, h:mm a");
        this.formatterScheduleSend[0] = createFormatter(locale, getStringInternal("SendTodayAt", mpEIGo.juqQQs.esbSDO.R.string.SendTodayAt), "'Send today at' HH:mm");
        this.formatterScheduleSend[1] = createFormatter(locale, getStringInternal("SendDayAt", mpEIGo.juqQQs.esbSDO.R.string.SendDayAt), "'Send on' MMM d 'at' HH:mm");
        this.formatterScheduleSend[2] = createFormatter(locale, getStringInternal("SendDayYearAt", mpEIGo.juqQQs.esbSDO.R.string.SendDayYearAt), "'Send on' MMM d yyyy 'at' HH:mm");
        this.formatterScheduleSend[3] = createFormatter(locale, getStringInternal("RemindTodayAt", mpEIGo.juqQQs.esbSDO.R.string.RemindTodayAt), "'Remind today at' HH:mm");
        this.formatterScheduleSend[4] = createFormatter(locale, getStringInternal("RemindDayAt", mpEIGo.juqQQs.esbSDO.R.string.RemindDayAt), "'Remind on' MMM d 'at' HH:mm");
        this.formatterScheduleSend[5] = createFormatter(locale, getStringInternal("RemindDayYearAt", mpEIGo.juqQQs.esbSDO.R.string.RemindDayYearAt), "'Remind on' MMM d yyyy 'at' HH:mm");
    }

    public static boolean isRTLCharacter(char ch) {
        return Character.getDirectionality(ch) == 1 || Character.getDirectionality(ch) == 2 || Character.getDirectionality(ch) == 16 || Character.getDirectionality(ch) == 17;
    }

    public static String formatSectionDate(long date) {
        long date2 = date * 1000;
        try {
            Calendar rightNow = Calendar.getInstance();
            int year = rightNow.get(1);
            rightNow.setTimeInMillis(date2);
            int dateYear = rightNow.get(1);
            int month = rightNow.get(2);
            String[] months = {getString("January", mpEIGo.juqQQs.esbSDO.R.string.January), getString("February", mpEIGo.juqQQs.esbSDO.R.string.February), getString("March", mpEIGo.juqQQs.esbSDO.R.string.March), getString("April", mpEIGo.juqQQs.esbSDO.R.string.April), getString("May", mpEIGo.juqQQs.esbSDO.R.string.May), getString("June", mpEIGo.juqQQs.esbSDO.R.string.June), getString("July", mpEIGo.juqQQs.esbSDO.R.string.July), getString("August", mpEIGo.juqQQs.esbSDO.R.string.August), getString("September", mpEIGo.juqQQs.esbSDO.R.string.September), getString("October", mpEIGo.juqQQs.esbSDO.R.string.October), getString("November", mpEIGo.juqQQs.esbSDO.R.string.November), getString("December", mpEIGo.juqQQs.esbSDO.R.string.December)};
            if (year == dateYear) {
                return months[month];
            }
            return months[month] + " " + dateYear;
        } catch (Exception e) {
            FileLog.e(e);
            return "LOC_ERR";
        }
    }

    public static String formatDateForBan(long date) {
        long date2 = date * 1000;
        try {
            Calendar rightNow = Calendar.getInstance();
            int year = rightNow.get(1);
            rightNow.setTimeInMillis(date2);
            int dateYear = rightNow.get(1);
            if (year == dateYear) {
                return getInstance().formatterBannedUntilThisYear.format(new Date(date2));
            }
            return getInstance().formatterBannedUntil.format(new Date(date2));
        } catch (Exception e) {
            FileLog.e(e);
            return "LOC_ERR";
        }
    }

    public static String stringForMessageListDate(long date) {
        long date2 = date * 1000;
        try {
            Calendar rightNow = Calendar.getInstance();
            int day = rightNow.get(6);
            rightNow.setTimeInMillis(date2);
            int dateDay = rightNow.get(6);
            if (Math.abs(System.currentTimeMillis() - date2) >= 31536000000L) {
                return getInstance().formatterYear.format(new Date(date2));
            }
            int dayDiff = dateDay - day;
            if (dayDiff != 0 && (dayDiff != -1 || System.currentTimeMillis() - date2 >= 28800000)) {
                if (dayDiff > -7 && dayDiff <= -1) {
                    return getInstance().formatterWeek.format(new Date(date2));
                }
                return getInstance().formatterDayMonth.format(new Date(date2));
            }
            return getInstance().formatterDay.format(new Date(date2));
        } catch (Exception e) {
            FileLog.e(e);
            return "LOC_ERR";
        }
    }

    public static String formatShortNumber(int number, int[] rounded) {
        StringBuilder K = new StringBuilder();
        int lastDec = 0;
        while (number / 1000 > 0) {
            K.append("K");
            lastDec = (number % 1000) / 100;
            number /= 1000;
        }
        if (rounded != null) {
            double value = ((double) number) + (((double) lastDec) / 10.0d);
            for (int a = 0; a < K.length(); a++) {
                value *= 1000.0d;
            }
            int a2 = (int) value;
            rounded[0] = a2;
        }
        return (lastDec == 0 || K.length() <= 0) ? K.length() == 2 ? String.format(Locale.US, "%dM", Integer.valueOf(number)) : String.format(Locale.US, "%d%s", Integer.valueOf(number), K.toString()) : K.length() == 2 ? String.format(Locale.US, "%d.%dM", Integer.valueOf(number), Integer.valueOf(lastDec)) : String.format(Locale.US, "%d.%d%s", Integer.valueOf(number), Integer.valueOf(lastDec), K.toString());
    }

    public static String formatUserStatus(int currentAccount, TLRPC.User user) {
        return formatUserStatus(currentAccount, user, null);
    }

    public static String formatUserStatus(int currentAccount, TLRPC.User user, boolean[] isOnline) {
        if (user != null && user.status != null && user.status.expires == 0) {
            if (user.status instanceof TLRPC.TL_userStatusRecently) {
                user.status.expires = -100;
            } else if (user.status instanceof TLRPC.TL_userStatusLastWeek) {
                user.status.expires = -101;
            } else if (user.status instanceof TLRPC.TL_userStatusLastMonth) {
                user.status.expires = ScreenAudioCapturer.ERROR_AUDIO_RECORD_INIT_EXCEPTION;
            }
        }
        if (user != null && user.status != null && user.status.expires <= 0 && MessagesController.getInstance(currentAccount).onlinePrivacy.containsKey(Integer.valueOf(user.id))) {
            if (isOnline != null) {
                isOnline[0] = true;
            }
            return getString("Online", mpEIGo.juqQQs.esbSDO.R.string.Online);
        }
        if (user == null || user.status == null || user.status.expires == 0 || UserObject.isDeleted(user) || (user instanceof TLRPC.TL_userEmpty)) {
            return getString("ALongTimeAgo", mpEIGo.juqQQs.esbSDO.R.string.ALongTimeAgo);
        }
        int currentTime = ConnectionsManager.getInstance(currentAccount).getCurrentTime();
        if (user.status.expires > currentTime) {
            if (isOnline != null) {
                isOnline[0] = true;
            }
            return getString("Online", mpEIGo.juqQQs.esbSDO.R.string.Online);
        }
        if (user.status.expires == -1) {
            return getString("Invisible", mpEIGo.juqQQs.esbSDO.R.string.Invisible);
        }
        if (user.status.expires == -100) {
            return getString("Lately", mpEIGo.juqQQs.esbSDO.R.string.Lately);
        }
        if (user.status.expires != -101) {
            if (user.status.expires == -102) {
                return getString("WithinAMonth", mpEIGo.juqQQs.esbSDO.R.string.WithinAMonth);
            }
            return formatDateOnline(user.status.expires);
        }
        return getString("WithinAWeek", mpEIGo.juqQQs.esbSDO.R.string.WithinAWeek);
    }

    public static String formatUserStatusNew(int currentAccount, TLRPC.User user, boolean[] isOnline) {
        if (user != null && user.status != null && user.status.expires == 0) {
            if (user.status instanceof TLRPC.TL_userStatusRecently) {
                user.status.expires = -100;
            } else if (user.status instanceof TLRPC.TL_userStatusLastWeek) {
                user.status.expires = -101;
            } else if (user.status instanceof TLRPC.TL_userStatusLastMonth) {
                user.status.expires = ScreenAudioCapturer.ERROR_AUDIO_RECORD_INIT_EXCEPTION;
            }
        }
        if (user != null && user.status != null && user.status.expires <= 0 && MessagesController.getInstance(currentAccount).onlinePrivacy.containsKey(Integer.valueOf(user.id))) {
            if (isOnline != null) {
                isOnline[0] = true;
            }
            return getString("New_Online", mpEIGo.juqQQs.esbSDO.R.string.New_Online);
        }
        if (user == null || user.status == null || user.status.expires == 0 || UserObject.isDeleted(user) || (user instanceof TLRPC.TL_userEmpty)) {
            return getString("ALongTimeAgo", mpEIGo.juqQQs.esbSDO.R.string.ALongTimeAgo);
        }
        int currentTime = ConnectionsManager.getInstance(currentAccount).getCurrentTime();
        if (user.status.expires > currentTime) {
            if (isOnline != null) {
                isOnline[0] = true;
            }
            return getString("New_Online", mpEIGo.juqQQs.esbSDO.R.string.New_Online);
        }
        if (user.status.expires == -1) {
            return getString("Invisible", mpEIGo.juqQQs.esbSDO.R.string.Invisible);
        }
        return user.status.expires == -100 ? formatString("LastSeenDays", mpEIGo.juqQQs.esbSDO.R.string.LastSeenDays, 1) : user.status.expires == -101 ? formatString("LastSeenDays", mpEIGo.juqQQs.esbSDO.R.string.LastSeenDays, 3) : user.status.expires == -102 ? formatString("LastSeenDays", mpEIGo.juqQQs.esbSDO.R.string.LastSeenDays, 15) : formatDateOnlineNew(user.status.expires);
    }

    private String escapeString(String str) {
        if (str.contains("[CDATA")) {
            return str;
        }
        return str.replace("<", "&lt;").replace(">", "&gt;").replace("& ", "&amp; ");
    }

    public void saveRemoteLocaleStringsForCurrentLocale(TLRPC.TL_langPackDifference difference, int currentAccount) {
        if (this.currentLocaleInfo == null) {
            return;
        }
        String langCode = difference.lang_code.replace('-', '_').toLowerCase();
        if (!langCode.equals(this.currentLocaleInfo.shortName) && !langCode.equals(this.currentLocaleInfo.baseLangCode)) {
            return;
        }
        lambda$null$9$LocaleController(this.currentLocaleInfo, difference, currentAccount);
    }

    /* JADX INFO: renamed from: saveRemoteLocaleStrings, reason: merged with bridge method [inline-methods] and merged with bridge method [inline-methods] and merged with bridge method [inline-methods] and merged with bridge method [inline-methods] */
    public void lambda$null$9$LocaleController(final LocaleInfo localeInfo, final TLRPC.TL_langPackDifference difference, int currentAccount) {
        int type;
        File finalFile;
        HashMap<String, String> values;
        if (difference == null || difference.strings.isEmpty() || localeInfo == null || localeInfo.isLocal()) {
            return;
        }
        String langCode = difference.lang_code.replace('-', '_').toLowerCase();
        if (langCode.equals(localeInfo.shortName)) {
            type = 0;
        } else if (langCode.equals(localeInfo.baseLangCode)) {
            type = 1;
        } else {
            type = -1;
        }
        if (type == -1) {
            return;
        }
        if (type == 0) {
            finalFile = localeInfo.getPathToFile();
        } else {
            File finalFile2 = localeInfo.getPathToBaseFile();
            finalFile = finalFile2;
        }
        try {
            if (difference.from_version == 0) {
                values = new HashMap<>();
            } else {
                values = getLocaleFileStrings(finalFile, true);
            }
            for (int a = 0; a < difference.strings.size(); a++) {
                TLRPC.LangPackString string = difference.strings.get(a);
                if (string instanceof TLRPC.TL_langPackString) {
                    values.put(string.key, escapeString(string.value));
                } else if (string instanceof TLRPC.TL_langPackStringPluralized) {
                    values.put(string.key + "_zero", string.zero_value != null ? escapeString(string.zero_value) : "");
                    values.put(string.key + "_one", string.one_value != null ? escapeString(string.one_value) : "");
                    values.put(string.key + "_two", string.two_value != null ? escapeString(string.two_value) : "");
                    values.put(string.key + "_few", string.few_value != null ? escapeString(string.few_value) : "");
                    values.put(string.key + "_many", string.many_value != null ? escapeString(string.many_value) : "");
                    values.put(string.key + "_other", string.other_value != null ? escapeString(string.other_value) : "");
                } else if (string instanceof TLRPC.TL_langPackStringDeleted) {
                    values.remove(string.key);
                }
            }
            if (BuildVars.LOGS_ENABLED) {
                FileLog.d("save locale file to " + finalFile);
            }
            BufferedWriter writer = new BufferedWriter(new FileWriter(finalFile));
            writer.write("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n");
            writer.write("<resources>\n");
            for (Map.Entry<String, String> entry : values.entrySet()) {
                writer.write(String.format("<string name=\"%1$s\">%2$s</string>\n", entry.getKey(), entry.getValue()));
            }
            writer.write("</resources>");
            writer.close();
            boolean hasBase = localeInfo.hasBaseLang();
            final HashMap<String, String> valuesToSet = getLocaleFileStrings(hasBase ? localeInfo.getPathToBaseFile() : localeInfo.getPathToFile());
            if (hasBase) {
                valuesToSet.putAll(getLocaleFileStrings(localeInfo.getPathToFile()));
            }
            final int i = type;
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$LocaleController$sWRhadVflzM93JWPJhWHgJ1TMQ4
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$saveRemoteLocaleStrings$4$LocaleController(localeInfo, i, difference, valuesToSet);
                }
            });
        } catch (Exception e) {
        }
    }

    public /* synthetic */ void lambda$saveRemoteLocaleStrings$4$LocaleController(LocaleInfo localeInfo, int type, TLRPC.TL_langPackDifference difference, HashMap valuesToSet) {
        String[] args;
        Locale newLocale;
        if (localeInfo != null) {
            if (type == 0) {
                localeInfo.version = difference.version;
            } else {
                localeInfo.baseVersion = difference.version;
            }
        }
        saveOtherLanguages();
        try {
            if (this.currentLocaleInfo == localeInfo) {
                if (!TextUtils.isEmpty(localeInfo.pluralLangCode)) {
                    args = localeInfo.pluralLangCode.split("_");
                } else if (!TextUtils.isEmpty(localeInfo.baseLangCode)) {
                    args = localeInfo.baseLangCode.split("_");
                } else {
                    args = localeInfo.shortName.split("_");
                }
                if (args.length == 1) {
                    newLocale = new Locale(args[0]);
                } else {
                    newLocale = new Locale(args[0], args[1]);
                }
                this.languageOverride = localeInfo.shortName;
                SharedPreferences preferences = MessagesController.getGlobalMainSettings();
                SharedPreferences.Editor editor = preferences.edit();
                editor.putString("language", localeInfo.getKey());
                editor.commit();
                this.localeValues = valuesToSet;
                this.currentLocale = newLocale;
                this.currentLocaleInfo = localeInfo;
                if (localeInfo != null && !TextUtils.isEmpty(localeInfo.pluralLangCode)) {
                    this.currentPluralRules = this.allRules.get(this.currentLocaleInfo.pluralLangCode);
                }
                if (this.currentPluralRules == null) {
                    PluralRules pluralRules = this.allRules.get(this.currentLocale.getLanguage());
                    this.currentPluralRules = pluralRules;
                    if (pluralRules == null) {
                        this.currentPluralRules = this.allRules.get("en");
                    }
                }
                this.changingConfiguration = true;
                Locale.setDefault(this.currentLocale);
                Configuration config = new Configuration();
                config.locale = this.currentLocale;
                ApplicationLoader.applicationContext.getResources().updateConfiguration(config, ApplicationLoader.applicationContext.getResources().getDisplayMetrics());
                this.changingConfiguration = false;
            }
        } catch (Exception e) {
            FileLog.e(e);
            this.changingConfiguration = false;
        }
        recreateFormatters();
        NotificationCenter.getGlobalInstance().postNotificationName(NotificationCenter.reloadInterface, new Object[0]);
    }

    public void loadRemoteLanguages(int currentAccount) {
    }

    private /* synthetic */ void lambda$loadRemoteLanguages$6(final int currentAccount, final TLObject response, TLRPC.TL_error error) {
        if (response != null) {
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$LocaleController$2aK8qbJ1wIYoLlrhdAvVsHJngP0
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$null$5$LocaleController(response, currentAccount);
                }
            });
        }
    }

    public /* synthetic */ void lambda$null$5$LocaleController(TLObject response, int currentAccount) {
        this.loadingRemoteLanguages = false;
        TLRPC.Vector res = (TLRPC.Vector) response;
        int size = this.remoteLanguages.size();
        for (int a = 0; a < size; a++) {
            this.remoteLanguages.get(a).serverIndex = Integer.MAX_VALUE;
        }
        int size2 = res.objects.size();
        for (int a2 = 0; a2 < size2; a2++) {
            TLRPC.TL_langPackLanguage language = (TLRPC.TL_langPackLanguage) res.objects.get(a2);
            if (BuildVars.LOGS_ENABLED) {
                FileLog.d("loaded lang " + language.name);
            }
            LocaleInfo localeInfo = new LocaleInfo();
            localeInfo.nameEnglish = language.name;
            localeInfo.name = language.native_name;
            localeInfo.shortName = language.lang_code.replace('-', '_').toLowerCase();
            if (language.base_lang_code != null) {
                localeInfo.baseLangCode = language.base_lang_code.replace('-', '_').toLowerCase();
            } else {
                localeInfo.baseLangCode = "";
            }
            localeInfo.pluralLangCode = language.plural_code.replace('-', '_').toLowerCase();
            localeInfo.pathToFile = "remote";
            localeInfo.serverIndex = a2;
            LocaleInfo existing = getLanguageFromDict(localeInfo.getKey());
            if (existing == null) {
                this.languages.add(localeInfo);
                this.languagesDict.put(localeInfo.getKey(), localeInfo);
            } else {
                existing.nameEnglish = localeInfo.nameEnglish;
                existing.name = localeInfo.name;
                existing.baseLangCode = localeInfo.baseLangCode;
                existing.pluralLangCode = localeInfo.pluralLangCode;
                existing.pathToFile = localeInfo.pathToFile;
                existing.serverIndex = localeInfo.serverIndex;
                localeInfo = existing;
            }
            if (!this.remoteLanguagesDict.containsKey(localeInfo.getKey())) {
                this.remoteLanguages.add(localeInfo);
                this.remoteLanguagesDict.put(localeInfo.getKey(), localeInfo);
            }
        }
        int a3 = 0;
        while (a3 < this.remoteLanguages.size()) {
            LocaleInfo info = this.remoteLanguages.get(a3);
            if (info.serverIndex == Integer.MAX_VALUE && info != this.currentLocaleInfo) {
                if (BuildVars.LOGS_ENABLED) {
                    FileLog.d("remove lang " + info.getKey());
                }
                this.remoteLanguages.remove(a3);
                this.remoteLanguagesDict.remove(info.getKey());
                this.languages.remove(info);
                this.languagesDict.remove(info.getKey());
                a3--;
            }
            a3++;
        }
        saveOtherLanguages();
        NotificationCenter.getGlobalInstance().postNotificationName(NotificationCenter.suggestedLangpack, new Object[0]);
        applyLanguage(this.currentLocaleInfo, true, false, currentAccount);
    }

    private void applyRemoteLanguage(final LocaleInfo localeInfo, String langCode, boolean force, final int currentAccount) {
        if (localeInfo != null) {
            if (localeInfo != null && !localeInfo.isRemote() && !localeInfo.isUnofficial()) {
                return;
            }
            if (localeInfo.hasBaseLang() && (langCode == null || langCode.equals(localeInfo.baseLangCode))) {
                if (localeInfo.baseVersion != 0 && !force) {
                    if (localeInfo.hasBaseLang()) {
                        TLRPC.TL_langpack_getDifference req = new TLRPC.TL_langpack_getDifference();
                        req.from_version = localeInfo.baseVersion;
                        req.lang_code = localeInfo.getBaseLangCode();
                        req.lang_pack = "";
                        ConnectionsManager.getInstance(currentAccount).sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$LocaleController$OMBxhTNEtpsvH8xZB1EEE8z-_rs
                            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                                this.f$0.lambda$applyRemoteLanguage$8$LocaleController(localeInfo, currentAccount, tLObject, tL_error);
                            }
                        }, 8);
                    }
                } else {
                    TLRPC.TL_langpack_getLangPack req2 = new TLRPC.TL_langpack_getLangPack();
                    req2.lang_code = localeInfo.getBaseLangCode();
                    ConnectionsManager.getInstance(currentAccount).sendRequest(req2, new RequestDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$LocaleController$YlQ82GLqaaWELCXQPHxjJkKCP0s
                        @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                        public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                            this.f$0.lambda$applyRemoteLanguage$10$LocaleController(localeInfo, currentAccount, tLObject, tL_error);
                        }
                    }, 8);
                }
            }
            if (langCode == null || langCode.equals(localeInfo.shortName)) {
                if (localeInfo.version != 0 && !force) {
                    TLRPC.TL_langpack_getDifference req3 = new TLRPC.TL_langpack_getDifference();
                    req3.from_version = localeInfo.version;
                    req3.lang_code = localeInfo.getLangCode();
                    req3.lang_pack = "";
                    ConnectionsManager.getInstance(currentAccount).sendRequest(req3, new RequestDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$LocaleController$KiVn_ZVPi8P8eUMYU6PkvonVs5Y
                        @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                        public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                            this.f$0.lambda$applyRemoteLanguage$12$LocaleController(localeInfo, currentAccount, tLObject, tL_error);
                        }
                    }, 8);
                    return;
                }
                for (int a = 0; a < 3; a++) {
                    ConnectionsManager.setLangCode(localeInfo.getLangCode());
                }
                TLRPC.TL_langpack_getLangPack req4 = new TLRPC.TL_langpack_getLangPack();
                req4.lang_code = localeInfo.getLangCode();
                ConnectionsManager.getInstance(currentAccount).sendRequest(req4, new RequestDelegate() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$LocaleController$sSojWjUqBSr4BlxWpUk4cDqcunU
                    @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                    public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                        this.f$0.lambda$applyRemoteLanguage$14$LocaleController(localeInfo, currentAccount, tLObject, tL_error);
                    }
                }, 8);
            }
        }
    }

    public /* synthetic */ void lambda$applyRemoteLanguage$8$LocaleController(final LocaleInfo localeInfo, final int currentAccount, final TLObject response, TLRPC.TL_error error) {
        if (response != null) {
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$LocaleController$iZYLmh-WBWKIlxJJBHYPqj75pGw
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$null$7$LocaleController(localeInfo, response, currentAccount);
                }
            });
        }
    }

    public /* synthetic */ void lambda$applyRemoteLanguage$10$LocaleController(final LocaleInfo localeInfo, final int currentAccount, final TLObject response, TLRPC.TL_error error) {
        if (response != null) {
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$LocaleController$dn4E-LqjVDAqlBCN_EPbYknePuY
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$null$9$LocaleController(localeInfo, response, currentAccount);
                }
            });
        }
    }

    public /* synthetic */ void lambda$applyRemoteLanguage$12$LocaleController(final LocaleInfo localeInfo, final int currentAccount, final TLObject response, TLRPC.TL_error error) {
        if (response != null) {
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$LocaleController$-5H_mgfC84HOXTsqXQvIEls94cg
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$null$11$LocaleController(localeInfo, response, currentAccount);
                }
            });
        }
    }

    public /* synthetic */ void lambda$applyRemoteLanguage$14$LocaleController(final LocaleInfo localeInfo, final int currentAccount, final TLObject response, TLRPC.TL_error error) {
        if (response != null) {
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.-$$Lambda$LocaleController$u-xrcisf6DhLnp0C9c-7vwaNUsk
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$null$13$LocaleController(localeInfo, response, currentAccount);
                }
            });
        }
    }

    public String getTranslitString(String src) {
        return getTranslitString(src, true, false);
    }

    public String getTranslitString(String src, boolean onlyEnglish) {
        return getTranslitString(src, true, onlyEnglish);
    }

    public String getTranslitString(String src, boolean ru, boolean onlyEnglish) {
        String str;
        String str2;
        String str3;
        String str4;
        String str5;
        String str6;
        String str7;
        String str8;
        String str9;
        if (src == null) {
            return null;
        }
        if (this.ruTranslitChars != null) {
            str = "m";
            str2 = ImageLoader.AUTOPLAY_FILTER;
            str3 = "r";
            str4 = "z";
            str5 = "h";
            str6 = TtmlNode.TAG_P;
            str7 = "v";
            str8 = "u";
            str9 = "s";
        } else {
            HashMap<String, String> map = new HashMap<>(33);
            this.ruTranslitChars = map;
            map.put("а", "a");
            this.ruTranslitChars.put("б", "b");
            this.ruTranslitChars.put("в", "v");
            this.ruTranslitChars.put("г", ImageLoader.AUTOPLAY_FILTER);
            this.ruTranslitChars.put("д", "d");
            this.ruTranslitChars.put("е", "e");
            HashMap<String, String> map2 = this.ruTranslitChars;
            str2 = ImageLoader.AUTOPLAY_FILTER;
            map2.put("ё", "yo");
            this.ruTranslitChars.put("ж", "zh");
            this.ruTranslitChars.put("з", "z");
            this.ruTranslitChars.put("и", "i");
            this.ruTranslitChars.put("й", "i");
            this.ruTranslitChars.put("к", "k");
            this.ruTranslitChars.put("л", "l");
            this.ruTranslitChars.put("м", "m");
            this.ruTranslitChars.put("н", "n");
            this.ruTranslitChars.put("о", "o");
            this.ruTranslitChars.put("п", TtmlNode.TAG_P);
            str = "m";
            str3 = "r";
            this.ruTranslitChars.put("р", str3);
            str4 = "z";
            this.ruTranslitChars.put("с", "s");
            str7 = "v";
            this.ruTranslitChars.put("т", "t");
            str8 = "u";
            this.ruTranslitChars.put("у", str8);
            str9 = "s";
            this.ruTranslitChars.put("ф", "f");
            str5 = "h";
            this.ruTranslitChars.put("х", str5);
            HashMap<String, String> map3 = this.ruTranslitChars;
            str6 = TtmlNode.TAG_P;
            map3.put("ц", "ts");
            this.ruTranslitChars.put("ч", "ch");
            this.ruTranslitChars.put("ш", ShellAdbUtils.COMMAND_SH);
            this.ruTranslitChars.put("щ", "sch");
            this.ruTranslitChars.put("ы", "i");
            this.ruTranslitChars.put("ь", "");
            this.ruTranslitChars.put("ъ", "");
            this.ruTranslitChars.put("э", "e");
            this.ruTranslitChars.put("ю", "yu");
            this.ruTranslitChars.put("я", "ya");
        }
        if (this.translitChars == null) {
            HashMap<String, String> map4 = new HashMap<>(487);
            this.translitChars = map4;
            map4.put("ȼ", "c");
            this.translitChars.put("ᶇ", "n");
            this.translitChars.put("ɖ", "d");
            this.translitChars.put("ỿ", "y");
            this.translitChars.put("ᴓ", "o");
            this.translitChars.put("ø", "o");
            this.translitChars.put("ḁ", "a");
            this.translitChars.put("ʯ", str5);
            this.translitChars.put("ŷ", "y");
            this.translitChars.put("ʞ", "k");
            this.translitChars.put("ừ", str8);
            String str10 = str8;
            this.translitChars.put("ꜳ", "aa");
            this.translitChars.put("ĳ", "ij");
            this.translitChars.put("ḽ", "l");
            this.translitChars.put("ɪ", "i");
            this.translitChars.put("ḇ", "b");
            this.translitChars.put("ʀ", str3);
            this.translitChars.put("ě", "e");
            this.translitChars.put("ﬃ", "ffi");
            this.translitChars.put("ơ", "o");
            this.translitChars.put("ⱹ", str3);
            this.translitChars.put("ồ", "o");
            this.translitChars.put("ǐ", "i");
            String str11 = str6;
            this.translitChars.put("ꝕ", str11);
            this.translitChars.put("ý", "y");
            this.translitChars.put("ḝ", "e");
            this.translitChars.put("ₒ", "o");
            this.translitChars.put("ⱥ", "a");
            this.translitChars.put("ʙ", "b");
            this.translitChars.put("ḛ", "e");
            this.translitChars.put("ƈ", "c");
            this.translitChars.put("ɦ", str5);
            this.translitChars.put("ᵬ", "b");
            String str12 = str5;
            String str13 = str9;
            this.translitChars.put("ṣ", str13);
            this.translitChars.put("đ", "d");
            this.translitChars.put("ỗ", "o");
            this.translitChars.put("ɟ", "j");
            this.translitChars.put("ẚ", "a");
            this.translitChars.put("ɏ", "y");
            this.translitChars.put("ʌ", str7);
            this.translitChars.put("ꝓ", str11);
            this.translitChars.put("ﬁ", "fi");
            this.translitChars.put("ᶄ", "k");
            this.translitChars.put("ḏ", "d");
            this.translitChars.put("ᴌ", "l");
            this.translitChars.put("ė", "e");
            this.translitChars.put("ᴋ", "k");
            this.translitChars.put("ċ", "c");
            this.translitChars.put("ʁ", str3);
            this.translitChars.put("ƕ", "hv");
            this.translitChars.put("ƀ", "b");
            this.translitChars.put("ṍ", "o");
            this.translitChars.put("ȣ", "ou");
            this.translitChars.put("ǰ", "j");
            String str14 = str2;
            this.translitChars.put("ᶃ", str14);
            this.translitChars.put("ṋ", "n");
            this.translitChars.put("ɉ", "j");
            this.translitChars.put("ǧ", str14);
            this.translitChars.put("ǳ", "dz");
            String str15 = str4;
            this.translitChars.put("ź", str15);
            this.translitChars.put("ꜷ", "au");
            this.translitChars.put("ǖ", str10);
            this.translitChars.put("ᵹ", str14);
            this.translitChars.put("ȯ", "o");
            this.translitChars.put("ɐ", "a");
            this.translitChars.put("ą", "a");
            this.translitChars.put("õ", "o");
            this.translitChars.put("ɻ", str3);
            this.translitChars.put("ꝍ", "o");
            this.translitChars.put("ǟ", "a");
            this.translitChars.put("ȴ", "l");
            this.translitChars.put("ʂ", str13);
            this.translitChars.put("ﬂ", "fl");
            this.translitChars.put("ȉ", "i");
            this.translitChars.put("ⱻ", "e");
            this.translitChars.put("ṉ", "n");
            this.translitChars.put("ï", "i");
            this.translitChars.put("ñ", "n");
            this.translitChars.put("ᴉ", "i");
            this.translitChars.put("ʇ", "t");
            this.translitChars.put("ẓ", str15);
            this.translitChars.put("ỷ", "y");
            this.translitChars.put("ȳ", "y");
            this.translitChars.put("ṩ", str13);
            this.translitChars.put("ɽ", str3);
            this.translitChars.put("ĝ", str14);
            this.translitChars.put("ᴝ", str10);
            this.translitChars.put("ḳ", "k");
            this.translitChars.put("ꝫ", "et");
            this.translitChars.put("ī", "i");
            this.translitChars.put("ť", "t");
            this.translitChars.put("ꜿ", "c");
            this.translitChars.put("ʟ", "l");
            this.translitChars.put("ꜹ", "av");
            this.translitChars.put("û", str10);
            this.translitChars.put("æ", "ae");
            this.translitChars.put("ă", "a");
            this.translitChars.put("ǘ", str10);
            this.translitChars.put("ꞅ", str13);
            this.translitChars.put("ᵣ", str3);
            this.translitChars.put("ᴀ", "a");
            this.translitChars.put("ƃ", "b");
            this.translitChars.put("ḩ", str12);
            this.translitChars.put("ṧ", str13);
            this.translitChars.put("ₑ", "e");
            this.translitChars.put("ʜ", str12);
            this.translitChars.put("ẋ", "x");
            this.translitChars.put("ꝅ", "k");
            this.translitChars.put("ḋ", "d");
            this.translitChars.put("ƣ", "oi");
            this.translitChars.put("ꝑ", str11);
            this.translitChars.put("ħ", str12);
            String str16 = str7;
            this.translitChars.put("ⱴ", str16);
            this.translitChars.put("ẇ", "w");
            this.translitChars.put("ǹ", "n");
            String str17 = str;
            this.translitChars.put("ɯ", str17);
            this.translitChars.put("ɡ", str14);
            this.translitChars.put("ɴ", "n");
            this.translitChars.put("ᴘ", str11);
            this.translitChars.put("ᵥ", str16);
            this.translitChars.put("ū", str10);
            this.translitChars.put("ḃ", "b");
            this.translitChars.put("ṗ", str11);
            this.translitChars.put("å", "a");
            this.translitChars.put("ɕ", "c");
            this.translitChars.put("ọ", "o");
            this.translitChars.put("ắ", "a");
            this.translitChars.put("ƒ", "f");
            this.translitChars.put("ǣ", "ae");
            this.translitChars.put("ꝡ", "vy");
            this.translitChars.put("ﬀ", "ff");
            this.translitChars.put("ᶉ", str3);
            this.translitChars.put("ô", "o");
            this.translitChars.put("ǿ", "o");
            this.translitChars.put("ṳ", str10);
            this.translitChars.put("ȥ", str15);
            this.translitChars.put("ḟ", "f");
            this.translitChars.put("ḓ", "d");
            this.translitChars.put("ȇ", "e");
            this.translitChars.put("ȕ", str10);
            this.translitChars.put("ȵ", "n");
            this.translitChars.put("ʠ", "q");
            this.translitChars.put("ấ", "a");
            this.translitChars.put("ǩ", "k");
            this.translitChars.put("ĩ", "i");
            this.translitChars.put("ṵ", str10);
            this.translitChars.put("ŧ", "t");
            this.translitChars.put("ɾ", str3);
            this.translitChars.put("ƙ", "k");
            this.translitChars.put("ṫ", "t");
            this.translitChars.put("ꝗ", "q");
            this.translitChars.put("ậ", "a");
            this.translitChars.put("ʄ", "j");
            this.translitChars.put("ƚ", "l");
            this.translitChars.put("ᶂ", "f");
            this.translitChars.put("ᵴ", str13);
            this.translitChars.put("ꞃ", str3);
            this.translitChars.put("ᶌ", str16);
            this.translitChars.put("ɵ", "o");
            this.translitChars.put("ḉ", "c");
            this.translitChars.put("ᵤ", str10);
            this.translitChars.put("ẑ", str15);
            this.translitChars.put("ṹ", str10);
            this.translitChars.put("ň", "n");
            this.translitChars.put("ʍ", "w");
            this.translitChars.put("ầ", "a");
            this.translitChars.put("ǉ", "lj");
            this.translitChars.put("ɓ", "b");
            this.translitChars.put("ɼ", str3);
            this.translitChars.put("ò", "o");
            this.translitChars.put("ẘ", "w");
            this.translitChars.put("ɗ", "d");
            this.translitChars.put("ꜽ", "ay");
            this.translitChars.put("ư", str10);
            this.translitChars.put("ᶀ", "b");
            this.translitChars.put("ǜ", str10);
            this.translitChars.put("ẹ", "e");
            this.translitChars.put("ǡ", "a");
            this.translitChars.put("ɥ", str12);
            this.translitChars.put("ṏ", "o");
            this.translitChars.put("ǔ", str10);
            this.translitChars.put("ʎ", "y");
            this.translitChars.put("ȱ", "o");
            this.translitChars.put("ệ", "e");
            this.translitChars.put("ế", "e");
            this.translitChars.put("ĭ", "i");
            this.translitChars.put("ⱸ", "e");
            this.translitChars.put("ṯ", "t");
            this.translitChars.put("ᶑ", "d");
            this.translitChars.put("ḧ", str12);
            this.translitChars.put("ṥ", str13);
            this.translitChars.put("ë", "e");
            this.translitChars.put("ᴍ", str17);
            this.translitChars.put("ö", "o");
            this.translitChars.put("é", "e");
            this.translitChars.put("ı", "i");
            this.translitChars.put("ď", "d");
            this.translitChars.put("ᵯ", str17);
            this.translitChars.put("ỵ", "y");
            this.translitChars.put("ŵ", "w");
            this.translitChars.put("ề", "e");
            this.translitChars.put("ứ", str10);
            this.translitChars.put("ƶ", str15);
            this.translitChars.put("ĵ", "j");
            this.translitChars.put("ḍ", "d");
            this.translitChars.put("ŭ", str10);
            this.translitChars.put("ʝ", "j");
            this.translitChars.put("ê", "e");
            this.translitChars.put("ǚ", str10);
            this.translitChars.put("ġ", str14);
            this.translitChars.put("ṙ", str3);
            this.translitChars.put("ƞ", "n");
            this.translitChars.put("ḗ", "e");
            this.translitChars.put("ẝ", str13);
            this.translitChars.put("ᶁ", "d");
            this.translitChars.put("ķ", "k");
            this.translitChars.put("ᴂ", "ae");
            this.translitChars.put("ɘ", "e");
            this.translitChars.put("ợ", "o");
            this.translitChars.put("ḿ", str17);
            this.translitChars.put("ꜰ", "f");
            this.translitChars.put("ẵ", "a");
            this.translitChars.put("ꝏ", "oo");
            this.translitChars.put("ᶆ", str17);
            this.translitChars.put("ᵽ", str11);
            this.translitChars.put("ữ", str10);
            this.translitChars.put("ⱪ", "k");
            this.translitChars.put("ḥ", str12);
            this.translitChars.put("ţ", "t");
            this.translitChars.put("ᵱ", str11);
            this.translitChars.put("ṁ", str17);
            this.translitChars.put("á", "a");
            this.translitChars.put("ᴎ", "n");
            this.translitChars.put("ꝟ", str16);
            this.translitChars.put("è", "e");
            this.translitChars.put("ᶎ", str15);
            this.translitChars.put("ꝺ", "d");
            this.translitChars.put("ᶈ", str11);
            this.translitChars.put("ɫ", "l");
            this.translitChars.put("ᴢ", str15);
            this.translitChars.put("ɱ", str17);
            this.translitChars.put("ṝ", str3);
            this.translitChars.put("ṽ", str16);
            this.translitChars.put("ũ", str10);
            this.translitChars.put("ß", DownloadAction.TYPE_SS);
            this.translitChars.put("ĥ", str12);
            this.translitChars.put("ᵵ", "t");
            this.translitChars.put("ʐ", str15);
            this.translitChars.put("ṟ", str3);
            this.translitChars.put("ɲ", "n");
            this.translitChars.put("à", "a");
            this.translitChars.put("ẙ", "y");
            this.translitChars.put("ỳ", "y");
            this.translitChars.put("ᴔ", "oe");
            this.translitChars.put("ₓ", "x");
            this.translitChars.put("ȗ", str10);
            this.translitChars.put("ⱼ", "j");
            this.translitChars.put("ẫ", "a");
            this.translitChars.put("ʑ", str15);
            this.translitChars.put("ẛ", str13);
            this.translitChars.put("ḭ", "i");
            this.translitChars.put("ꜵ", "ao");
            this.translitChars.put("ɀ", str15);
            this.translitChars.put("ÿ", "y");
            this.translitChars.put("ǝ", "e");
            this.translitChars.put("ǭ", "o");
            this.translitChars.put("ᴅ", "d");
            this.translitChars.put("ᶅ", "l");
            this.translitChars.put("ù", str10);
            this.translitChars.put("ạ", "a");
            this.translitChars.put("ḅ", "b");
            this.translitChars.put("ụ", str10);
            this.translitChars.put("ằ", "a");
            this.translitChars.put("ᴛ", "t");
            this.translitChars.put("ƴ", "y");
            this.translitChars.put("ⱦ", "t");
            this.translitChars.put("ⱡ", "l");
            this.translitChars.put("ȷ", "j");
            this.translitChars.put("ᵶ", str15);
            this.translitChars.put("ḫ", str12);
            this.translitChars.put("ⱳ", "w");
            this.translitChars.put("ḵ", "k");
            this.translitChars.put("ờ", "o");
            this.translitChars.put("î", "i");
            this.translitChars.put("ģ", str14);
            this.translitChars.put("ȅ", "e");
            this.translitChars.put("ȧ", "a");
            this.translitChars.put("ẳ", "a");
            this.translitChars.put("ɋ", "q");
            this.translitChars.put("ṭ", "t");
            this.translitChars.put("ꝸ", "um");
            this.translitChars.put("ᴄ", "c");
            this.translitChars.put("ẍ", "x");
            this.translitChars.put("ủ", str10);
            this.translitChars.put("ỉ", "i");
            this.translitChars.put("ᴚ", str3);
            this.translitChars.put("ś", str13);
            this.translitChars.put("ꝋ", "o");
            this.translitChars.put("ỹ", "y");
            this.translitChars.put("ṡ", str13);
            this.translitChars.put("ǌ", "nj");
            this.translitChars.put("ȁ", "a");
            this.translitChars.put("ẗ", "t");
            this.translitChars.put("ĺ", "l");
            this.translitChars.put("ž", str15);
            this.translitChars.put("ᵺ", "th");
            this.translitChars.put("ƌ", "d");
            this.translitChars.put("ș", str13);
            this.translitChars.put("š", str13);
            this.translitChars.put("ᶙ", str10);
            this.translitChars.put("ẽ", "e");
            this.translitChars.put("ẜ", str13);
            this.translitChars.put("ɇ", "e");
            this.translitChars.put("ṷ", str10);
            this.translitChars.put("ố", "o");
            this.translitChars.put("ȿ", str13);
            this.translitChars.put("ᴠ", str16);
            this.translitChars.put("ꝭ", "is");
            this.translitChars.put("ᴏ", "o");
            this.translitChars.put("ɛ", "e");
            this.translitChars.put("ǻ", "a");
            this.translitChars.put("ﬄ", "ffl");
            this.translitChars.put("ⱺ", "o");
            this.translitChars.put("ȋ", "i");
            this.translitChars.put("ᵫ", "ue");
            this.translitChars.put("ȡ", "d");
            this.translitChars.put("ⱬ", str15);
            this.translitChars.put("ẁ", "w");
            this.translitChars.put("ᶏ", "a");
            this.translitChars.put("ꞇ", "t");
            this.translitChars.put("ğ", str14);
            this.translitChars.put("ɳ", "n");
            this.translitChars.put("ʛ", str14);
            this.translitChars.put("ᴜ", str10);
            this.translitChars.put("ẩ", "a");
            this.translitChars.put("ṅ", "n");
            this.translitChars.put("ɨ", "i");
            this.translitChars.put("ᴙ", str3);
            this.translitChars.put("ǎ", "a");
            this.translitChars.put("ſ", str13);
            this.translitChars.put("ȫ", "o");
            this.translitChars.put("ɿ", str3);
            this.translitChars.put("ƭ", "t");
            this.translitChars.put("ḯ", "i");
            this.translitChars.put("ǽ", "ae");
            this.translitChars.put("ⱱ", str16);
            this.translitChars.put("ɶ", "oe");
            this.translitChars.put("ṃ", str17);
            this.translitChars.put("ż", str15);
            this.translitChars.put("ĕ", "e");
            this.translitChars.put("ꜻ", "av");
            this.translitChars.put("ở", "o");
            this.translitChars.put("ễ", "e");
            this.translitChars.put("ɬ", "l");
            this.translitChars.put("ị", "i");
            this.translitChars.put("ᵭ", "d");
            this.translitChars.put("ﬆ", "st");
            this.translitChars.put("ḷ", "l");
            this.translitChars.put("ŕ", str3);
            this.translitChars.put("ᴕ", "ou");
            this.translitChars.put("ʈ", "t");
            this.translitChars.put("ā", "a");
            this.translitChars.put("ḙ", "e");
            this.translitChars.put("ᴑ", "o");
            this.translitChars.put("ç", "c");
            this.translitChars.put("ᶊ", str13);
            this.translitChars.put("ặ", "a");
            this.translitChars.put("ų", str10);
            this.translitChars.put("ả", "a");
            this.translitChars.put("ǥ", str14);
            this.translitChars.put("ꝁ", "k");
            this.translitChars.put("ẕ", str15);
            this.translitChars.put("ŝ", str13);
            this.translitChars.put("ḕ", "e");
            this.translitChars.put("ɠ", str14);
            this.translitChars.put("ꝉ", "l");
            this.translitChars.put("ꝼ", "f");
            this.translitChars.put("ᶍ", "x");
            this.translitChars.put("ǒ", "o");
            this.translitChars.put("ę", "e");
            this.translitChars.put("ổ", "o");
            this.translitChars.put("ƫ", "t");
            this.translitChars.put("ǫ", "o");
            this.translitChars.put("i̇", "i");
            this.translitChars.put("ṇ", "n");
            this.translitChars.put("ć", "c");
            this.translitChars.put("ᵷ", str14);
            this.translitChars.put("ẅ", "w");
            this.translitChars.put("ḑ", "d");
            this.translitChars.put("ḹ", "l");
            this.translitChars.put("œ", "oe");
            this.translitChars.put("ᵳ", str3);
            this.translitChars.put("ļ", "l");
            this.translitChars.put("ȑ", str3);
            this.translitChars.put("ȭ", "o");
            this.translitChars.put("ᵰ", "n");
            this.translitChars.put("ᴁ", "ae");
            this.translitChars.put("ŀ", "l");
            this.translitChars.put("ä", "a");
            this.translitChars.put("ƥ", str11);
            this.translitChars.put("ỏ", "o");
            this.translitChars.put("į", "i");
            this.translitChars.put("ȓ", str3);
            this.translitChars.put("ǆ", "dz");
            this.translitChars.put("ḡ", str14);
            this.translitChars.put("ṻ", str10);
            this.translitChars.put("ō", "o");
            this.translitChars.put("ľ", "l");
            this.translitChars.put("ẃ", "w");
            this.translitChars.put("ț", "t");
            this.translitChars.put("ń", "n");
            this.translitChars.put("ɍ", str3);
            this.translitChars.put("ȃ", "a");
            this.translitChars.put("ü", str10);
            this.translitChars.put("ꞁ", "l");
            this.translitChars.put("ᴐ", "o");
            this.translitChars.put("ớ", "o");
            this.translitChars.put("ᴃ", "b");
            this.translitChars.put("ɹ", str3);
            this.translitChars.put("ᵲ", str3);
            this.translitChars.put("ʏ", "y");
            this.translitChars.put("ᵮ", "f");
            this.translitChars.put("ⱨ", str12);
            this.translitChars.put("ŏ", "o");
            this.translitChars.put("ú", str10);
            this.translitChars.put("ṛ", str3);
            this.translitChars.put("ʮ", str12);
            this.translitChars.put("ó", "o");
            this.translitChars.put("ů", str10);
            this.translitChars.put("ỡ", "o");
            this.translitChars.put("ṕ", str11);
            this.translitChars.put("ᶖ", "i");
            this.translitChars.put("ự", str10);
            this.translitChars.put("ã", "a");
            this.translitChars.put("ᵢ", "i");
            this.translitChars.put("ṱ", "t");
            this.translitChars.put("ể", "e");
            this.translitChars.put("ử", str10);
            this.translitChars.put("í", "i");
            this.translitChars.put("ɔ", "o");
            this.translitChars.put("ɺ", str3);
            this.translitChars.put("ɢ", str14);
            this.translitChars.put("ř", str3);
            this.translitChars.put("ẖ", str12);
            this.translitChars.put("ű", str10);
            this.translitChars.put("ȍ", "o");
            this.translitChars.put("ḻ", "l");
            this.translitChars.put("ḣ", str12);
            this.translitChars.put("ȶ", "t");
            this.translitChars.put("ņ", "n");
            this.translitChars.put("ᶒ", "e");
            this.translitChars.put("ì", "i");
            this.translitChars.put("ẉ", "w");
            this.translitChars.put("ē", "e");
            this.translitChars.put("ᴇ", "e");
            this.translitChars.put("ł", "l");
            this.translitChars.put("ộ", "o");
            this.translitChars.put("ɭ", "l");
            this.translitChars.put("ẏ", "y");
            this.translitChars.put("ᴊ", "j");
            this.translitChars.put("ḱ", "k");
            this.translitChars.put("ṿ", str16);
            this.translitChars.put("ȩ", "e");
            this.translitChars.put("â", "a");
            this.translitChars.put("ş", str13);
            this.translitChars.put("ŗ", str3);
            this.translitChars.put("ʋ", str16);
            this.translitChars.put("ₐ", "a");
            this.translitChars.put("ↄ", "c");
            this.translitChars.put("ᶓ", "e");
            this.translitChars.put("ɰ", str17);
            this.translitChars.put("ᴡ", "w");
            this.translitChars.put("ȏ", "o");
            this.translitChars.put("č", "c");
            this.translitChars.put("ǵ", str14);
            this.translitChars.put("ĉ", "c");
            this.translitChars.put("ᶗ", "o");
            this.translitChars.put("ꝃ", "k");
            this.translitChars.put("ꝙ", "q");
            this.translitChars.put("ṑ", "o");
            this.translitChars.put("ꜱ", str13);
            this.translitChars.put("ṓ", "o");
            this.translitChars.put("ȟ", str12);
            this.translitChars.put("ő", "o");
            this.translitChars.put("ꜩ", "tz");
            this.translitChars.put("ẻ", "e");
        }
        StringBuilder dst = new StringBuilder(src.length());
        int len = src.length();
        boolean upperCase = false;
        for (int a = 0; a < len; a++) {
            String ch = src.substring(a, a + 1);
            if (onlyEnglish) {
                String lower = ch.toLowerCase();
                upperCase = !ch.equals(lower);
                ch = lower;
            }
            String tch = this.translitChars.get(ch);
            if (tch == null && ru) {
                tch = this.ruTranslitChars.get(ch);
            }
            if (tch != null) {
                if (onlyEnglish && upperCase) {
                    tch = tch.length() > 1 ? tch.substring(0, 1).toUpperCase() + tch.substring(1) : tch.toUpperCase();
                }
                dst.append(tch);
            } else {
                if (onlyEnglish) {
                    char c = ch.charAt(0);
                    if ((c < 'a' || c > 'z' || c < '0' || c > '9') && c != ' ' && c != '\'' && c != ',' && c != '.' && c != '&' && c != '-' && c != '/') {
                        return null;
                    }
                    if (upperCase) {
                        ch = ch.toUpperCase();
                    }
                }
                dst.append(ch);
            }
        }
        return dst.toString();
    }

    public static class PluralRules_Zero extends PluralRules {
        @Override // im.uwrkaxlmjj.messenger.LocaleController.PluralRules
        public int quantityForNumber(int count) {
            if (count == 0 || count == 1) {
                return 2;
            }
            return 0;
        }
    }

    public static class PluralRules_Welsh extends PluralRules {
        @Override // im.uwrkaxlmjj.messenger.LocaleController.PluralRules
        public int quantityForNumber(int count) {
            if (count == 0) {
                return 1;
            }
            if (count == 1) {
                return 2;
            }
            if (count == 2) {
                return 4;
            }
            if (count == 3) {
                return 8;
            }
            if (count == 6) {
                return 16;
            }
            return 0;
        }
    }

    public static class PluralRules_Two extends PluralRules {
        @Override // im.uwrkaxlmjj.messenger.LocaleController.PluralRules
        public int quantityForNumber(int count) {
            if (count == 1) {
                return 2;
            }
            if (count == 2) {
                return 4;
            }
            return 0;
        }
    }

    public static class PluralRules_Tachelhit extends PluralRules {
        @Override // im.uwrkaxlmjj.messenger.LocaleController.PluralRules
        public int quantityForNumber(int count) {
            if (count >= 0 && count <= 1) {
                return 2;
            }
            if (count >= 2 && count <= 10) {
                return 8;
            }
            return 0;
        }
    }

    public static class PluralRules_Slovenian extends PluralRules {
        @Override // im.uwrkaxlmjj.messenger.LocaleController.PluralRules
        public int quantityForNumber(int count) {
            int rem100 = count % 100;
            if (rem100 == 1) {
                return 2;
            }
            if (rem100 == 2) {
                return 4;
            }
            if (rem100 >= 3 && rem100 <= 4) {
                return 8;
            }
            return 0;
        }
    }

    public static class PluralRules_Romanian extends PluralRules {
        @Override // im.uwrkaxlmjj.messenger.LocaleController.PluralRules
        public int quantityForNumber(int count) {
            int rem100 = count % 100;
            if (count == 1) {
                return 2;
            }
            if (count != 0) {
                if (rem100 >= 1 && rem100 <= 19) {
                    return 8;
                }
                return 0;
            }
            return 8;
        }
    }

    public static class PluralRules_Polish extends PluralRules {
        @Override // im.uwrkaxlmjj.messenger.LocaleController.PluralRules
        public int quantityForNumber(int count) {
            int rem100 = count % 100;
            int rem10 = count % 10;
            if (count == 1) {
                return 2;
            }
            if (rem10 >= 2 && rem10 <= 4 && (rem100 < 12 || rem100 > 14)) {
                return 8;
            }
            if (rem10 >= 0 && rem10 <= 1) {
                return 16;
            }
            if (rem10 < 5 || rem10 > 9) {
                if (rem100 >= 12 && rem100 <= 14) {
                    return 16;
                }
                return 0;
            }
            return 16;
        }
    }

    public static class PluralRules_One extends PluralRules {
        @Override // im.uwrkaxlmjj.messenger.LocaleController.PluralRules
        public int quantityForNumber(int count) {
            return count == 1 ? 2 : 0;
        }
    }

    public static class PluralRules_None extends PluralRules {
        @Override // im.uwrkaxlmjj.messenger.LocaleController.PluralRules
        public int quantityForNumber(int count) {
            return 0;
        }
    }

    public static class PluralRules_Maltese extends PluralRules {
        @Override // im.uwrkaxlmjj.messenger.LocaleController.PluralRules
        public int quantityForNumber(int count) {
            int rem100 = count % 100;
            if (count == 1) {
                return 2;
            }
            if (count != 0) {
                if (rem100 >= 2 && rem100 <= 10) {
                    return 8;
                }
                if (rem100 >= 11 && rem100 <= 19) {
                    return 16;
                }
                return 0;
            }
            return 8;
        }
    }

    public static class PluralRules_Macedonian extends PluralRules {
        @Override // im.uwrkaxlmjj.messenger.LocaleController.PluralRules
        public int quantityForNumber(int count) {
            if (count % 10 == 1 && count != 11) {
                return 2;
            }
            return 0;
        }
    }

    public static class PluralRules_Lithuanian extends PluralRules {
        @Override // im.uwrkaxlmjj.messenger.LocaleController.PluralRules
        public int quantityForNumber(int count) {
            int rem100 = count % 100;
            int rem10 = count % 10;
            if (rem10 == 1 && (rem100 < 11 || rem100 > 19)) {
                return 2;
            }
            if (rem10 >= 2 && rem10 <= 9) {
                if (rem100 < 11 || rem100 > 19) {
                    return 8;
                }
                return 0;
            }
            return 0;
        }
    }

    public static class PluralRules_Latvian extends PluralRules {
        @Override // im.uwrkaxlmjj.messenger.LocaleController.PluralRules
        public int quantityForNumber(int count) {
            if (count == 0) {
                return 1;
            }
            if (count % 10 == 1 && count % 100 != 11) {
                return 2;
            }
            return 0;
        }
    }

    public static class PluralRules_Langi extends PluralRules {
        @Override // im.uwrkaxlmjj.messenger.LocaleController.PluralRules
        public int quantityForNumber(int count) {
            if (count == 0) {
                return 1;
            }
            return (count <= 0 || count >= 2) ? 0 : 2;
        }
    }

    public static class PluralRules_French extends PluralRules {
        @Override // im.uwrkaxlmjj.messenger.LocaleController.PluralRules
        public int quantityForNumber(int count) {
            return (count < 0 || count >= 2) ? 0 : 2;
        }
    }

    public static class PluralRules_Czech extends PluralRules {
        @Override // im.uwrkaxlmjj.messenger.LocaleController.PluralRules
        public int quantityForNumber(int count) {
            if (count == 1) {
                return 2;
            }
            if (count >= 2 && count <= 4) {
                return 8;
            }
            return 0;
        }
    }

    public static class PluralRules_Breton extends PluralRules {
        @Override // im.uwrkaxlmjj.messenger.LocaleController.PluralRules
        public int quantityForNumber(int count) {
            if (count == 0) {
                return 1;
            }
            if (count == 1) {
                return 2;
            }
            if (count == 2) {
                return 4;
            }
            if (count == 3) {
                return 8;
            }
            if (count == 6) {
                return 16;
            }
            return 0;
        }
    }

    public static class PluralRules_Balkan extends PluralRules {
        @Override // im.uwrkaxlmjj.messenger.LocaleController.PluralRules
        public int quantityForNumber(int count) {
            int rem100 = count % 100;
            int rem10 = count % 10;
            if (rem10 == 1 && rem100 != 11) {
                return 2;
            }
            if (rem10 >= 2 && rem10 <= 4 && (rem100 < 12 || rem100 > 14)) {
                return 8;
            }
            if (rem10 == 0) {
                return 16;
            }
            if (rem10 < 5 || rem10 > 9) {
                if (rem100 >= 11 && rem100 <= 14) {
                    return 16;
                }
                return 0;
            }
            return 16;
        }
    }

    public static class PluralRules_Arabic extends PluralRules {
        @Override // im.uwrkaxlmjj.messenger.LocaleController.PluralRules
        public int quantityForNumber(int count) {
            int rem100 = count % 100;
            if (count == 0) {
                return 1;
            }
            if (count == 1) {
                return 2;
            }
            if (count == 2) {
                return 4;
            }
            if (rem100 >= 3 && rem100 <= 10) {
                return 8;
            }
            if (rem100 >= 11 && rem100 <= 99) {
                return 16;
            }
            return 0;
        }
    }

    public static String addNbsp(String src) {
        return src.replace(' ', Typography.nbsp);
    }

    public static void resetImperialSystemType() {
        useImperialSystemType = null;
    }

    public static String formatDistance(float distance) {
        String arg;
        String arg2;
        if (useImperialSystemType == null) {
            if (SharedConfig.distanceSystemType == 0) {
                try {
                    TelephonyManager telephonyManager = (TelephonyManager) ApplicationLoader.applicationContext.getSystemService("phone");
                    if (telephonyManager != null) {
                        String country = telephonyManager.getSimCountryIso().toUpperCase();
                        useImperialSystemType = Boolean.valueOf("US".equals(country) || "GB".equals(country) || "MM".equals(country) || "LR".equals(country));
                    }
                } catch (Exception e) {
                    useImperialSystemType = false;
                    FileLog.e(e);
                }
            } else {
                useImperialSystemType = Boolean.valueOf(SharedConfig.distanceSystemType == 2);
            }
        }
        if (!useImperialSystemType.booleanValue()) {
            if (distance < 1000.0f) {
                return formatString("MetersAway2", mpEIGo.juqQQs.esbSDO.R.string.MetersAway2, String.format("%d", Integer.valueOf((int) Math.max(1.0f, distance))));
            }
            if (distance % 1000.0f == 0.0f) {
                arg = String.format("%d", Integer.valueOf((int) (distance / 1000.0f)));
            } else {
                arg = String.format("%.2f", Float.valueOf(distance / 1000.0f));
            }
            return formatString("KMetersAway2", mpEIGo.juqQQs.esbSDO.R.string.KMetersAway2, arg);
        }
        float distance2 = distance * 3.28084f;
        if (distance2 < 1000.0f) {
            return formatString("FootsAway", mpEIGo.juqQQs.esbSDO.R.string.FootsAway, String.format("%d", Integer.valueOf((int) Math.max(1.0f, distance2))));
        }
        if (distance2 % 5280.0f == 0.0f) {
            arg2 = String.format("%d", Integer.valueOf((int) (distance2 / 5280.0f)));
        } else {
            arg2 = String.format("%.2f", Float.valueOf(distance2 / 5280.0f));
        }
        return formatString("MilesAway", mpEIGo.juqQQs.esbSDO.R.string.MilesAway, arg2);
    }
}
