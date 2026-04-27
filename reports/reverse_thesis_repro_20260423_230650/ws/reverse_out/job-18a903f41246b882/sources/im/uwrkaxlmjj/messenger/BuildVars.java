package im.uwrkaxlmjj.messenger;

import com.bjz.comm.net.SPConstant;

/* JADX INFO: loaded from: classes2.dex */
public class BuildVars {
    public static final boolean ALLOW_ADD_OUT_ACCOUNT = true;
    public static final boolean APP_ALLOW_REPOST_IMAGE = true;
    public static final boolean APP_ALLOW_REPOST_VIDEO = true;
    public static final boolean APP_ALLOW_SAVE_IMAGE = true;
    public static final boolean APP_ALLOW_SAVE_VIDEO = true;
    public static final boolean APP_NOT_GROUP_ADMIN = false;
    public static final boolean APP_OPEN_Collection = false;
    public static final boolean APP_OPEN_MM = false;
    public static final boolean APP_OUT_GROUP = true;
    public static final String COMPANY_TAG = "Sbcc";
    public static final boolean DISABLE_EMULATOR_INSTALL = true;
    public static final int EDITION_PERSONAL = 0;
    public static final boolean ENABLE_AUTHORIZATION_CODE_LOGIN = false;
    public static final boolean ENABLE_CHANGE_SYSTEM_NAME = false;
    public static final boolean ENABLE_CHARGE_WITHDRAW_TIP = true;
    public static final boolean ENABLE_CHAT_ATTACH_LOCATION_TOGGLE = false;
    public static final boolean ENABLE_CHAT_DOCUMENT_TOGGLE = false;
    public static final boolean ENABLE_CHAT_HAD_EDIT = false;
    public static final boolean ENABLE_CHAT_SHOW_WHO_TAKE_RED_PACKET = false;
    public static final boolean ENABLE_EDIT_ACCOUNT = true;
    public static final boolean ENABLE_FIXED_CHANNEL_ID = false;
    public static final boolean ENABLE_HOME_PAGE_BOTTOM_ITEM_SHOW_NET_PIC = false;
    public static final boolean ENABLE_HOME_PAGE_SHOW_WETAB_BOTTOM = false;
    public static final boolean ENABLE_HOME_PAGE_SHOW_WETAB_SIX_BOTTOM = false;
    public static final boolean ENABLE_ONLY_LOGIN = false;
    public static final boolean ENABLE_PERSONAL_DETAIL_NOTE = true;
    public static final boolean ENABLE_QR_CODE = false;
    public static final boolean ENABLE_SHIELD_ACCOUNT_CONFIG = true;
    public static final boolean ENABLE_SHIELD_DELETE_CONTACT = true;
    public static final boolean ENABLE_SHIELD_DELETE_MESSAGE = true;
    public static final boolean ENABLE_SHIELD_EDIT_MESSAGE = true;
    public static final boolean ENABLE_SHIELD_GROUP_SHARE = false;
    public static final boolean ENABLE_SHIELD_ONLINE_STATUE_SET = true;
    public static final boolean ENABLE_SHOW_GROUP_LIST_NON_ADMIN = false;
    public static final boolean ENABLE_SHOW_GROUP_ONLINE_COUNTS = true;
    public static final boolean ENABLE_SHOW_INVITE_MORE = true;
    public static final boolean ENABLE_SHOW_MINI_PROGRAM_FLOATING_BOX = false;
    public static final boolean ENABLE_SHOW_MINI_PROGRAM_VERIFICATION_CODE = false;
    public static final boolean ENABLE_SHOW_Reception_Number = false;
    public static final boolean ENABLE_SHOW_SESSION_ACTIVE = false;
    public static final boolean ENABLE_SIGN_PAGE_AGREEMENT_CHECKBOX = false;
    public static final boolean ENABLE_SIGN_UP_PAGE_IS_FIRST = true;
    public static final boolean ENABLE_SIGN_UP_USER_AVATAR = false;
    public static final boolean ENABLE_SIGN_UP_USER_DATE_BIRTHDAY = false;
    public static final boolean ENABLE_SIGN_UP_USER_GENDER = false;
    public static final boolean ENABLE_SIGN_UP_USER_NICKNAME = true;
    public static final boolean ENABLE_SUPPORT_IMAGE_CODE = false;
    public static final boolean ENABLE_SUPPORT_MODIFY_USER_GENDER_IN_USER_PAGE = false;
    public static final boolean ENABLE_SUPPORT_ONLINE_STATUE_SHOW = true;
    public static final boolean ENABLE_SUPPORT_OPEN_DEFAULT_LANGUAGE = false;
    public static final boolean ENABLE_SUPPORT_OPEN_INSTALL = false;
    public static final boolean ENABLE_SUPPORT_SECRET_CHAT = false;
    public static final boolean ENABLE_SUPPORT_SIGN_UP_INVITE_CODE = false;
    public static final boolean ENABLE_SUPPORT_VIDEO_CALL = true;
    public static final boolean ENABLE_SUPPORT_VOICE_CALL = true;
    public static final boolean ENABLE_TWO_STEP_CHECK = true;
    public static final boolean ENABLE_USE_GOOGLE_VERIFICATION_CODE = false;
    public static final boolean ENABLE_USE_GOOGLE_VERIFICATION_CODE_NEW = true;
    public static final String EN_APP_NAME = "Sbcc";
    public static final boolean HIDE_CHARGE_BUTTON = false;
    public static final boolean HIDE_WITHDRAW_BUTTON = false;
    public static final boolean IS_SHOW_RED_PACKET_AMOUNT = true;
    public static final boolean IS_SHOW_VIDEO_BG = true;
    public static final String MAX_REDPKT = "10000";
    public static final boolean OPEN_ADD_FRIENDS = true;
    public static final String OP_CHANNEL_ID = "";
    public static final int SIGN_UP_ACCOUNT_MAX_LENGTH = 32;
    public static final int SIGN_UP_ACCOUNT_MIN_LENGTH = 5;
    public static final String SYSTEM_NAME = "số hệ thống";
    public static int APP_ID = 30915;
    public static String APP_HASH = "fb9f0bb7fdd0760c354cc3d80cecb1d9";
    public static int BUILD_VERSION = 1;
    public static String BUILD_VERSION_STRING = com.bjz.comm.net.BuildConfig.VERSION_NAME;
    public static boolean VOIP_DEBUG = ApplicationLoader.applicationContext.getResources().getBoolean(mpEIGo.juqQQs.esbSDO.R.bool.voip_debug);
    public static boolean DEBUG_VERSION = ApplicationLoader.applicationContext.getResources().getBoolean(mpEIGo.juqQQs.esbSDO.R.bool.debug_version);
    public static boolean LOGS_ENABLED = ApplicationLoader.applicationContext.getResources().getBoolean(mpEIGo.juqQQs.esbSDO.R.bool.logs_enabled);
    public static boolean RELEASE_VERSION = ApplicationLoader.applicationContext.getResources().getBoolean(mpEIGo.juqQQs.esbSDO.R.bool.release);
    public static boolean DEBUG_PRIVATE_VERSION = true;
    public static boolean USE_CLOUD_STRINGS = true;
    public static String SMS_HASH = "";
    public static String PLAYSTORE_APP_URL = "";
    public static int EDITION = 0;
    public static boolean PHONE_CHECK = false;
    public static boolean WALLET_RED_PACKET_ENABLE = false;
    public static boolean WALLET_ENABLE = false;
    public static boolean ENABLE_ME_ONLINE_SERVICE = false;
    public static boolean ENABLE_ME_ABOUT_APP = false;

    static {
        if (ApplicationLoader.applicationContext != null) {
            ApplicationLoader.applicationContext.getSharedPreferences(SPConstant.SP_SYSTEM_CONFIG, 0);
        }
    }
}
