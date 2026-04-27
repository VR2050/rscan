package im.uwrkaxlmjj.ui.actionbar;

import android.content.Context;
import android.content.SharedPreferences;
import android.content.res.ColorStateList;
import android.content.res.Resources;
import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.ColorFilter;
import android.graphics.Paint;
import android.graphics.PorterDuff;
import android.graphics.PorterDuffColorFilter;
import android.graphics.PorterDuffXfermode;
import android.graphics.Rect;
import android.graphics.RectF;
import android.graphics.drawable.BitmapDrawable;
import android.graphics.drawable.ColorDrawable;
import android.graphics.drawable.Drawable;
import android.graphics.drawable.GradientDrawable;
import android.graphics.drawable.NinePatchDrawable;
import android.graphics.drawable.RippleDrawable;
import android.graphics.drawable.ShapeDrawable;
import android.graphics.drawable.StateListDrawable;
import android.graphics.drawable.shapes.OvalShape;
import android.graphics.drawable.shapes.RoundRectShape;
import android.hardware.Sensor;
import android.hardware.SensorEvent;
import android.hardware.SensorEventListener;
import android.hardware.SensorManager;
import android.net.Uri;
import android.os.Build;
import android.os.SystemClock;
import android.text.TextPaint;
import android.text.TextUtils;
import android.util.StateSet;
import androidx.core.internal.view.SupportMenu;
import androidx.core.view.ViewCompat;
import androidx.recyclerview.widget.ItemTouchHelper;
import com.google.android.exoplayer2.C;
import com.zhy.http.okhttp.OkHttpUtils;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.ApplicationLoader;
import im.uwrkaxlmjj.messenger.BuildVars;
import im.uwrkaxlmjj.messenger.FileLoader;
import im.uwrkaxlmjj.messenger.FileLog;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.messenger.MediaController;
import im.uwrkaxlmjj.messenger.MessagesController;
import im.uwrkaxlmjj.messenger.NotificationCenter;
import im.uwrkaxlmjj.messenger.SharedConfig;
import im.uwrkaxlmjj.messenger.UserConfig;
import im.uwrkaxlmjj.messenger.Utilities;
import im.uwrkaxlmjj.messenger.time.SunDate;
import im.uwrkaxlmjj.messenger.utils.status.SystemBarTintManager;
import im.uwrkaxlmjj.tgnet.ConnectionsManager;
import im.uwrkaxlmjj.tgnet.RequestDelegate;
import im.uwrkaxlmjj.tgnet.SerializedData;
import im.uwrkaxlmjj.tgnet.TLObject;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.components.BackgroundGradientDrawable;
import im.uwrkaxlmjj.ui.components.CombinedDrawable;
import im.uwrkaxlmjj.ui.components.RLottieDrawable;
import im.uwrkaxlmjj.ui.components.ScamDrawable;
import im.uwrkaxlmjj.ui.components.banner.config.BannerConfig;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Array;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import mpEIGo.juqQQs.esbSDO.R;
import org.json.JSONArray;
import org.json.JSONObject;

/* JADX INFO: loaded from: classes5.dex */
public class Theme {
    public static final int ACTION_BAR_AUDIO_SELECTOR_COLOR = 788529152;
    public static final int ACTION_BAR_MEDIA_PICKER_COLOR = -13421773;
    public static final int ACTION_BAR_PHOTO_VIEWER_COLOR = 2130706432;
    public static final int ACTION_BAR_PICKER_SELECTOR_COLOR = -12763843;
    public static final int ACTION_BAR_PLAYER_COLOR = -1;
    public static final int ACTION_BAR_VIDEO_EDIT_COLOR = -16777216;
    public static final int ACTION_BAR_WHITE_SELECTOR_COLOR = 1090519039;
    public static final int ARTICLE_VIEWER_MEDIA_PROGRESS_COLOR = -1;
    public static final int AUTO_NIGHT_TYPE_AUTOMATIC = 2;
    public static final int AUTO_NIGHT_TYPE_NONE = 0;
    public static final int AUTO_NIGHT_TYPE_SCHEDULED = 1;
    private static Field BitmapDrawable_mColorFilter = null;
    public static final long DEFAULT_BACKGROUND_ID = 1000001;
    private static final int LIGHT_SENSOR_THEME_SWITCH_DELAY = 1800;
    private static final int LIGHT_SENSOR_THEME_SWITCH_NEAR_DELAY = 12000;
    private static final int LIGHT_SENSOR_THEME_SWITCH_NEAR_THRESHOLD = 12000;
    private static final float MAXIMUM_LUX_BREAKPOINT = 500.0f;
    private static Method StateListDrawable_getStateDrawableMethod = null;
    public static final long THEME_BACKGROUND_ID = -2;
    private static SensorEventListener ambientSensorListener = null;
    private static HashMap<String, Integer> animatingColors = null;
    public static float autoNightBrighnessThreshold = 0.0f;
    public static String autoNightCityName = null;
    public static int autoNightDayEndTime = 0;
    public static int autoNightDayStartTime = 0;
    public static int autoNightLastSunCheckDay = 0;
    public static double autoNightLocationLatitude = 0.0d;
    public static double autoNightLocationLongitude = 0.0d;
    public static boolean autoNightScheduleByLocation = false;
    public static int autoNightSunriseTime = 0;
    public static int autoNightSunsetTime = 0;
    public static Paint avatar_backgroundPaint = null;
    public static Drawable avatar_ghostDrawable = null;
    public static Drawable avatar_savedDrawable = null;
    public static Drawable calllog_msgCallDownGreenDrawable = null;
    public static Drawable calllog_msgCallDownRedDrawable = null;
    public static Drawable calllog_msgCallUpGreenDrawable = null;
    public static Drawable calllog_msgCallUpRedDrawable = null;
    private static boolean canStartHolidayAnimation = false;
    public static Paint chat_actionBackgroundPaint = null;
    public static Paint chat_actionBackgroundPaint2 = null;
    public static TextPaint chat_actionTextPaint = null;
    public static TextPaint chat_adminPaint = null;
    public static Drawable chat_attachEmptyDrawable = null;
    public static TextPaint chat_audioPerformerPaint = null;
    public static TextPaint chat_audioTimePaint = null;
    public static TextPaint chat_audioTitlePaint = null;
    public static TextPaint chat_botButtonPaint = null;
    public static Drawable chat_botInlineDrawable = null;
    public static Drawable chat_botLinkDrawalbe = null;
    public static Paint chat_botProgressPaint = null;
    public static TextPaint chat_captionTextPaint = null;
    public static Paint chat_composeBackgroundPaint = null;
    public static Drawable chat_composeShadowDrawable = null;
    public static TextPaint chat_contactNamePaint = null;
    public static TextPaint chat_contactPhonePaint = null;
    public static TextPaint chat_contextResult_descriptionTextPaint = null;
    public static Drawable chat_contextResult_shadowUnderSwitchDrawable = null;
    public static TextPaint chat_contextResult_titleTextPaint = null;
    public static Paint chat_deleteProgressPaint = null;
    public static Paint chat_docBackPaint = null;
    public static TextPaint chat_docNamePaint = null;
    public static TextPaint chat_durationPaint = null;
    public static Drawable chat_fileApkIcon = null;
    public static Drawable chat_fileCompressIcon = null;
    public static Drawable chat_fileDocIcon = null;
    public static Drawable chat_fileIcon = null;
    public static Drawable chat_fileIpaIcon = null;
    public static Drawable chat_fileNoneIcon = null;
    public static Drawable chat_filePdfIcon = null;
    public static Drawable chat_fileTxtIcon = null;
    public static Drawable chat_fileXlsIcon = null;
    public static Drawable chat_flameIcon = null;
    public static TextPaint chat_forwardNamePaint = null;
    public static Drawable chat_gameInThunderBackground = null;
    public static Drawable chat_gameOutThunderBackground = null;
    public static TextPaint chat_gamePaint = null;
    public static Drawable chat_gifIcon = null;
    public static Drawable chat_goIconDrawable = null;
    public static TextPaint chat_infoPaint = null;
    public static Drawable chat_inlineResultAudio = null;
    public static Drawable chat_inlineResultFile = null;
    public static Drawable chat_inlineResultLocation = null;
    public static TextPaint chat_instantViewPaint = null;
    public static Paint chat_instantViewRectPaint = null;
    public static TextPaint chat_livePaint = null;
    public static TextPaint chat_locationAddressPaint = null;
    public static TextPaint chat_locationTitlePaint = null;
    public static Drawable chat_lockIconDrawable = null;
    public static Drawable chat_msgAudioBlueFlagIcon = null;
    public static Drawable chat_msgAvatarLiveLocationDrawable = null;
    public static TextPaint chat_msgBotButtonPaint = null;
    public static Drawable chat_msgBroadcastDrawable = null;
    public static Drawable chat_msgBroadcastMediaDrawable = null;
    public static Drawable chat_msgCallDownGreenDrawable = null;
    public static Drawable chat_msgCallDownRedDrawable = null;
    public static Drawable chat_msgCallUpGreenDrawable = null;
    public static Drawable chat_msgErrorDrawable = null;
    public static Paint chat_msgErrorPaint = null;
    public static TextPaint chat_msgGameTextPaint = null;
    public static Drawable chat_msgInAudioFlagIcon = null;
    public static Drawable chat_msgInCallDrawable = null;
    public static Drawable chat_msgInCallSelectedDrawable = null;
    public static Drawable chat_msgInClockDrawable = null;
    public static Drawable chat_msgInDrawable = null;
    public static Drawable chat_msgInInstantDrawable = null;
    public static Drawable chat_msgInMediaDrawable = null;
    public static Drawable chat_msgInMediaSelectedDrawable = null;
    public static Drawable chat_msgInMediaShadowDrawable = null;
    public static Drawable chat_msgInMenuDrawable = null;
    public static Drawable chat_msgInMenuSelectedDrawable = null;
    public static Drawable chat_msgInSelectedClockDrawable = null;
    public static Drawable chat_msgInSelectedDrawable = null;
    public static Drawable chat_msgInShadowDrawable = null;
    public static Drawable chat_msgInTranslateIcon = null;
    public static Drawable chat_msgInViewsDrawable = null;
    public static Drawable chat_msgInViewsSelectedDrawable = null;
    public static Drawable chat_msgLiveLogoDrawable = null;
    public static Drawable chat_msgMediaBroadcastDrawable = null;
    public static Drawable chat_msgMediaCheckDrawable = null;
    public static Drawable chat_msgMediaClockDrawable = null;
    public static Drawable chat_msgMediaHalfCheckDrawable = null;
    public static Drawable chat_msgMediaHalfGrayCheckDrawable = null;
    public static Drawable chat_msgMediaMenuDrawable = null;
    public static Drawable chat_msgMediaViewsDrawable = null;
    public static Drawable chat_msgNoSoundDrawable = null;
    public static Drawable chat_msgOutAudioFlagIcon = null;
    public static Drawable chat_msgOutBroadcastDrawable = null;
    public static Drawable chat_msgOutCallDrawable = null;
    public static Drawable chat_msgOutCallSelectedDrawable = null;
    public static Drawable chat_msgOutCheckDrawable = null;
    public static Drawable chat_msgOutCheckGrayDrawable = null;
    public static Drawable chat_msgOutCheckGraySelectedDrawable = null;
    public static Drawable chat_msgOutCheckReadDrawable = null;
    public static Drawable chat_msgOutCheckReadGrayDrawable = null;
    public static Drawable chat_msgOutCheckReadGraySelectedDrawable = null;
    public static Drawable chat_msgOutCheckReadSelectedDrawable = null;
    public static Drawable chat_msgOutCheckSelectedDrawable = null;
    public static Drawable chat_msgOutClockDrawable = null;
    public static Drawable chat_msgOutDrawable = null;
    public static Drawable chat_msgOutGrayClockDrawable = null;
    public static Drawable chat_msgOutGraySelectedClockDrawable = null;
    public static Drawable chat_msgOutHalfCheckDrawable = null;
    public static Drawable chat_msgOutHalfCheckSelectedDrawable = null;
    public static Drawable chat_msgOutHalfGrayCheckDrawable = null;
    public static Drawable chat_msgOutHalfGrayCheckSelectedDrawable = null;
    public static Drawable chat_msgOutInstantDrawable = null;
    public static Drawable chat_msgOutLocationDrawable = null;
    public static Drawable chat_msgOutMediaDrawable = null;
    public static Drawable chat_msgOutMediaSelectedDrawable = null;
    public static Drawable chat_msgOutMediaShadowDrawable = null;
    public static Drawable chat_msgOutMenuDrawable = null;
    public static Drawable chat_msgOutMenuSelectedDrawable = null;
    public static Drawable chat_msgOutSelectedClockDrawable = null;
    public static Drawable chat_msgOutSelectedDrawable = null;
    public static Drawable chat_msgOutShadowDrawable = null;
    public static Drawable chat_msgOutTranslateIcon = null;
    public static Drawable chat_msgOutVideoCallDrawable = null;
    public static Drawable chat_msgOutViewsDrawable = null;
    public static Drawable chat_msgOutViewsSelectedDrawable = null;
    public static Drawable chat_msgOutVoiceCallDrawable = null;
    public static Drawable chat_msgRedpkgCloudDrawable = null;
    public static Drawable chat_msgRedpkgInDrawable = null;
    public static Drawable chat_msgRedpkgInMediaDrawable = null;
    public static Drawable chat_msgRedpkgInMediaSelectedDrawable = null;
    public static Drawable chat_msgRedpkgInSelectedDrawable = null;
    public static Drawable chat_msgRedpkgOutDrawable = null;
    public static Drawable chat_msgRedpkgOutMediaDrawable = null;
    public static Drawable chat_msgRedpkgOutMediaSelectedDrawable = null;
    public static Drawable chat_msgRedpkgOutSelectedDrawable = null;
    public static Drawable chat_msgStickerCheckDrawable = null;
    public static Drawable chat_msgStickerClockDrawable = null;
    public static Drawable chat_msgStickerHalfCheckDrawable = null;
    public static Drawable chat_msgStickerHalfGrayCheckDrawable = null;
    public static Drawable chat_msgStickerViewsDrawable = null;
    public static TextPaint chat_msgTextPaint = null;
    public static TextPaint chat_msgTextPaintOneEmoji = null;
    public static TextPaint chat_msgTextPaintThreeEmoji = null;
    public static TextPaint chat_msgTextPaintTwoEmoji = null;
    public static Drawable chat_msgTransferBackIcon = null;
    public static Drawable chat_msgTransferNormalIcon = null;
    public static Drawable chat_msgTransferReceiveIcon = null;
    public static Drawable chat_msgVideoCallDrawable = null;
    public static Drawable chat_msgVoiceCallDrawable = null;
    public static Drawable chat_muteIconDrawable = null;
    public static TextPaint chat_namePaint = null;
    public static Paint chat_radialProgress2Paint = null;
    public static Paint chat_radialProgressPaint = null;
    public static Drawable chat_redLocationIcon = null;
    public static TextPaint chat_redpkgBackgoundPaint = null;
    public static Drawable chat_redpkgReceivedIcon = null;
    public static Drawable chat_redpkgSamllIcon = null;
    public static TextPaint chat_redpkgTextPaint = null;
    public static Drawable chat_redpkgUnreceivedIcon = null;
    public static Paint chat_replyBackgroundPaint = null;
    public static Drawable chat_replyIconDrawable = null;
    public static Paint chat_replyLinePaint = null;
    public static TextPaint chat_replyNamePaint = null;
    public static TextPaint chat_replyTextPaint = null;
    public static Drawable chat_roundVideoShadow = null;
    public static Drawable chat_shareDrawable = null;
    public static Drawable chat_shareIconDrawable = null;
    public static TextPaint chat_shipmentPaint = null;
    public static Paint chat_statusPaint = null;
    public static Paint chat_statusRecordPaint = null;
    public static Drawable chat_sysNotifyDrawable = null;
    public static Drawable chat_sysNotifyRightDrawable = null;
    public static Drawable chat_systemDrawable = null;
    public static Paint chat_textSearchSelectionPaint = null;
    public static Paint chat_timeBackgroundPaint = null;
    public static TextPaint chat_timePaint = null;
    public static TextPaint chat_translationPaint = null;
    public static Paint chat_urlPaint = null;
    public static Paint checkboxSquare_backgroundPaint = null;
    public static Paint checkboxSquare_checkPaint = null;
    public static Paint checkboxSquare_eraserPaint = null;
    public static PorterDuffColorFilter colorFilter = null;
    public static PorterDuffColorFilter colorFilter2 = null;
    public static PorterDuffColorFilter colorPressedFilter = null;
    public static PorterDuffColorFilter colorPressedFilter2 = null;
    private static int currentColor = 0;
    private static HashMap<String, Integer> currentColors = null;
    private static HashMap<String, Integer> currentColorsNoAccent = null;
    private static ThemeInfo currentDayTheme = null;
    private static ThemeInfo currentNightTheme = null;
    private static int currentSelectedColor = 0;
    private static ColorFilter currentShareColorFilter = null;
    private static int currentShareColorFilterColor = 0;
    private static ColorFilter currentShareSelectedColorFilter = null;
    private static int currentShareSelectedColorFilterColor = 0;
    private static ThemeInfo currentTheme = null;
    private static ThemeInfo defaultTheme = null;
    public static RLottieDrawable dialogs_archiveAvatarDrawable = null;
    public static boolean dialogs_archiveAvatarDrawableRecolored = false;
    public static RLottieDrawable dialogs_archiveDrawable = null;
    public static boolean dialogs_archiveDrawableRecolored = false;
    public static TextPaint dialogs_archiveTextPaint = null;
    public static Drawable dialogs_botDrawable = null;
    public static Drawable dialogs_broadcastDrawable = null;
    public static Drawable dialogs_checkDrawable = null;
    public static Drawable dialogs_checkReadDrawable = null;
    public static Drawable dialogs_checkReadDrawable1 = null;
    public static Drawable dialogs_clockDrawable = null;
    public static Paint dialogs_countGrayPaint = null;
    public static Paint dialogs_countPaint = null;
    public static TextPaint dialogs_countTextPaint = null;
    public static Drawable dialogs_deleteDrawable = null;
    public static Drawable dialogs_errorDrawable = null;
    public static Paint dialogs_errorPaint = null;
    public static Drawable dialogs_groupDrawable = null;
    public static Drawable dialogs_halfCheckDrawable = null;
    public static Drawable dialogs_halfCheckDrawable1 = null;
    public static Drawable dialogs_holidayDrawable = null;
    private static int dialogs_holidayDrawableOffsetX = 0;
    private static int dialogs_holidayDrawableOffsetY = 0;
    public static Drawable dialogs_lockDrawable = null;
    public static Drawable dialogs_mentionDrawable = null;
    public static Paint dialogs_menuPaint = null;
    public static TextPaint dialogs_messageNamePaint = null;
    public static TextPaint dialogs_messagePaint = null;
    public static TextPaint dialogs_messagePrintingPaint = null;
    public static Drawable dialogs_muteDrawable = null;
    public static TextPaint dialogs_nameEncryptedPaint = null;
    public static TextPaint dialogs_namePaint = null;
    public static TextPaint dialogs_offlinePaint = null;
    public static Paint dialogs_onlineCirclePaint = null;
    public static TextPaint dialogs_onlinePaint = null;
    public static RLottieDrawable dialogs_pinArchiveDrawable = null;
    public static Drawable dialogs_pinDrawable = null;
    public static Drawable dialogs_pinnedDrawable = null;
    public static Paint dialogs_pinnedPaint = null;
    public static Drawable dialogs_reorderDrawable = null;
    public static ScamDrawable dialogs_scamDrawable = null;
    public static TextPaint dialogs_searchNameEncryptedPaint = null;
    public static TextPaint dialogs_searchNamePaint = null;
    public static Paint dialogs_tabletSeletedPaint = null;
    public static TextPaint dialogs_timePaint = null;
    public static RLottieDrawable dialogs_unarchiveDrawable = null;
    public static RLottieDrawable dialogs_unpinArchiveDrawable = null;
    public static Drawable dialogs_verifiedCheckDrawable = null;
    public static Drawable dialogs_verifiedDrawable = null;
    public static Paint dividerPaint = null;
    private static boolean isCustomTheme = false;
    private static boolean isInNigthMode = false;
    private static boolean isPatternWallpaper = false;
    private static boolean isWallpaperMotion = false;
    private static Boolean isWallpaperMotionPrev = null;
    public static final String key_WalletPageBlueTextColor = "key_WalletPageBlueTextColor";
    public static final String key_accentBlue = "key_accentBlue";
    public static final String key_accentError = "key_accentError";
    public static final String key_accentOrange = "key_accentOrange";
    public static final String key_accentSafe = "key_accentSafe";
    public static final String key_accentSuccess = "key_accentSuccess";
    public static final String key_accentWarning = "key_accentWarning";
    public static final String key_actionBarActionModeDefault = "actionBarActionModeDefault";
    public static final String key_actionBarActionModeDefaultIcon = "actionBarActionModeDefaultIcon";
    public static final String key_actionBarActionModeDefaultSelector = "actionBarActionModeDefaultSelector";
    public static final String key_actionBarActionModeDefaultTop = "actionBarActionModeDefaultTop";
    public static final String key_actionBarBrowser = "actionBarBrowser";
    public static final String key_actionBarDefault = "actionBarDefault";
    public static final String key_actionBarDefaultArchived = "actionBarDefaultArchived";
    public static final String key_actionBarDefaultArchivedIcon = "actionBarDefaultArchivedIcon";
    public static final String key_actionBarDefaultArchivedSearch = "actionBarDefaultArchivedSearch";
    public static final String key_actionBarDefaultArchivedSearchPlaceholder = "actionBarDefaultSearchArchivedPlaceholder";
    public static final String key_actionBarDefaultArchivedSelector = "actionBarDefaultArchivedSelector";
    public static final String key_actionBarDefaultArchivedTitle = "actionBarDefaultArchivedTitle";
    public static final String key_actionBarDefaultIcon = "actionBarDefaultIcon";
    public static final String key_actionBarDefaultSearch = "actionBarDefaultSearch";
    public static final String key_actionBarDefaultSearchPlaceholder = "actionBarDefaultSearchPlaceholder";
    public static final String key_actionBarDefaultSelector = "actionBarDefaultSelector";
    public static final String key_actionBarDefaultSubmenuBackground = "actionBarDefaultSubmenuBackground";
    public static final String key_actionBarDefaultSubmenuItem = "actionBarDefaultSubmenuItem";
    public static final String key_actionBarDefaultSubmenuItemIcon = "actionBarDefaultSubmenuItemIcon";
    public static final String key_actionBarDefaultSubtitle = "actionBarDefaultSubtitle";
    public static final String key_actionBarDefaultTitle = "actionBarDefaultTitle";
    public static final String key_actionBarTabActiveText = "actionBarTabActiveText";
    public static final String key_actionBarTabLine = "actionBarTabLine";
    public static final String key_actionBarTabSelector = "actionBarTabSelector";
    public static final String key_actionBarTabUnactiveText = "actionBarTabUnactiveText";
    public static final String key_actionBarWhiteSelector = "actionBarWhiteSelector";
    public static final String key_avatar_actionBarIconBlue = "avatar_actionBarIconBlue";
    public static final String key_avatar_actionBarSelectorBlue = "avatar_actionBarSelectorBlue";
    public static final String key_avatar_backgroundActionBarBlue = "avatar_backgroundActionBarBlue";
    public static final String key_avatar_backgroundArchived = "avatar_backgroundArchived";
    public static final String key_avatar_backgroundArchivedHidden = "avatar_backgroundArchivedHidden";
    public static final String key_avatar_backgroundGroupCreateSpanBlue = "avatar_backgroundGroupCreateSpanBlue";
    public static final String key_avatar_backgroundInProfileBlue = "avatar_backgroundInProfileBlue";
    public static final String key_avatar_backgroundSaved = "avatar_backgroundSaved";
    public static final String key_avatar_subtitleInProfileBlue = "avatar_subtitleInProfileBlue";
    public static final String key_avatar_text = "avatar_text";
    public static final String key_blackAlpha30 = "key_blackAlpha30";
    public static final String key_blackAlpha70 = "key_blackAlpha70";
    public static final String key_blackAlpha80 = "key_blackAlpha80";
    public static final String key_bottomBarBackground = "bottomBarBackgroundColor";
    public static final String key_bottomBarNormalColor = "bottomBarNormalColor";
    public static final String key_bottomBarSelectedColor = "bottomBarSelectedColor";
    public static final String key_brandBG = "key_brandBG";
    public static final String key_brandDark = "key_brandDark";
    public static final String key_brandDarkMode = "key_brandDarkMode";
    public static final String key_brandDefault = "key_brandDefault";
    public static final String key_brandLight = "key_brandLight";
    public static final String key_calls_callReceivedGreenIcon = "calls_callReceivedGreenIcon";
    public static final String key_calls_callReceivedRedIcon = "calls_callReceivedRedIcon";
    public static final String key_changephoneinfo_image = "changephoneinfo_image";
    public static final String key_changephoneinfo_image2 = "changephoneinfo_image2";
    public static final String key_chat_addContact = "chat_addContact";
    public static final String key_chat_adminSelectedText = "chat_adminSelectedText";
    public static final String key_chat_adminText = "chat_adminText";
    public static final String key_chat_attachActiveTab = "chat_attachActiveTab";
    public static final String key_chat_attachAudioBackground = "chat_attachAudioBackground";
    public static final String key_chat_attachAudioIcon = "chat_attachAudioIcon";
    public static final String key_chat_attachCheckBoxBackground = "chat_attachCheckBoxBackground";
    public static final String key_chat_attachCheckBoxCheck = "chat_attachCheckBoxCheck";
    public static final String key_chat_attachContactBackground = "chat_attachContactBackground";
    public static final String key_chat_attachContactIcon = "chat_attachContactIcon";
    public static final String key_chat_attachEmptyImage = "chat_attachEmptyImage";
    public static final String key_chat_attachFileBackground = "chat_attachFileBackground";
    public static final String key_chat_attachFileIcon = "chat_attachFileIcon";
    public static final String key_chat_attachGalleryBackground = "chat_attachGalleryBackground";
    public static final String key_chat_attachGalleryIcon = "chat_attachGalleryIcon";
    public static final String key_chat_attachLocationBackground = "chat_attachLocationBackground";
    public static final String key_chat_attachLocationIcon = "chat_attachLocationIcon";
    public static final String key_chat_attachMediaBanBackground = "chat_attachMediaBanBackground";
    public static final String key_chat_attachMediaBanText = "chat_attachMediaBanText";
    public static final String key_chat_attachPermissionImage = "chat_attachPermissionImage";
    public static final String key_chat_attachPermissionMark = "chat_attachPermissionMark";
    public static final String key_chat_attachPermissionText = "chat_attachPermissionText";
    public static final String key_chat_attachPhotoBackground = "chat_attachPhotoBackground";
    public static final String key_chat_attachPollBackground = "chat_attachPollBackground";
    public static final String key_chat_attachPollIcon = "chat_attachPollIcon";
    public static final String key_chat_attachUnactiveTab = "chat_attachUnactiveTab";
    public static final String key_chat_botButtonText = "chat_botButtonText";
    public static final String key_chat_botKeyboardButtonBackground = "chat_botKeyboardButtonBackground";
    public static final String key_chat_botKeyboardButtonBackgroundPressed = "chat_botKeyboardButtonBackgroundPressed";
    public static final String key_chat_botKeyboardButtonText = "chat_botKeyboardButtonText";
    public static final String key_chat_botProgress = "chat_botProgress";
    public static final String key_chat_botSwitchToInlineText = "chat_botSwitchToInlineText";
    public static final String key_chat_emojiBottomPanelIcon = "chat_emojiBottomPanelIcon";
    public static final String key_chat_emojiPanelBackground = "chat_emojiPanelBackground";
    public static final String key_chat_emojiPanelBackspace = "chat_emojiPanelBackspace";
    public static final String key_chat_emojiPanelBadgeBackground = "chat_emojiPanelBadgeBackground";
    public static final String key_chat_emojiPanelBadgeText = "chat_emojiPanelBadgeText";
    public static final String key_chat_emojiPanelEmptyText = "chat_emojiPanelEmptyText";
    public static final String key_chat_emojiPanelIcon = "chat_emojiPanelIcon";
    public static final String key_chat_emojiPanelIconSelected = "chat_emojiPanelIconSelected";
    public static final String key_chat_emojiPanelMasksIcon = "chat_emojiPanelMasksIcon";
    public static final String key_chat_emojiPanelMasksIconSelected = "chat_emojiPanelMasksIconSelected";
    public static final String key_chat_emojiPanelNewTrending = "chat_emojiPanelNewTrending";
    public static final String key_chat_emojiPanelShadowLine = "chat_emojiPanelShadowLine";
    public static final String key_chat_emojiPanelStickerPackSelector = "chat_emojiPanelStickerPackSelector";
    public static final String key_chat_emojiPanelStickerPackSelectorLine = "chat_emojiPanelStickerPackSelectorLine";
    public static final String key_chat_emojiPanelStickerSetName = "chat_emojiPanelStickerSetName";
    public static final String key_chat_emojiPanelStickerSetNameHighlight = "chat_emojiPanelStickerSetNameHighlight";
    public static final String key_chat_emojiPanelStickerSetNameIcon = "chat_emojiPanelStickerSetNameIcon";
    public static final String key_chat_emojiPanelTrendingDescription = "chat_emojiPanelTrendingDescription";
    public static final String key_chat_emojiPanelTrendingTitle = "chat_emojiPanelTrendingTitle";
    public static final String key_chat_emojiSearchBackground = "chat_emojiSearchBackground";
    public static final String key_chat_emojiSearchIcon = "chat_emojiSearchIcon";
    public static final String key_chat_fieldOverlayText = "chat_fieldOverlayText";
    public static final String key_chat_gifSaveHintBackground = "chat_gifSaveHintBackground";
    public static final String key_chat_gifSaveHintText = "chat_gifSaveHintText";
    public static final String key_chat_goDownButton = "chat_goDownButton";
    public static final String key_chat_goDownButtonCounter = "chat_goDownButtonCounter";
    public static final String key_chat_goDownButtonCounterBackground = "chat_goDownButtonCounterBackground";
    public static final String key_chat_goDownButtonIcon = "chat_goDownButtonIcon";
    public static final String key_chat_goDownButtonShadow = "chat_goDownButtonShadow";
    public static final String key_chat_inAudioCacheSeekbar = "chat_inAudioCacheSeekbar";
    public static final String key_chat_inAudioDurationSelectedText = "chat_inAudioDurationSelectedText";
    public static final String key_chat_inAudioDurationText = "chat_inAudioDurationText";
    public static final String key_chat_inAudioPerformerSelectedText = "chat_inAudioPerfomerSelectedText";
    public static final String key_chat_inAudioPerformerText = "chat_inAudioPerfomerText";
    public static final String key_chat_inAudioProgress = "chat_inAudioProgress";
    public static final String key_chat_inAudioSeekbar = "chat_inAudioSeekbar";
    public static final String key_chat_inAudioSeekbarFill = "chat_inAudioSeekbarFill";
    public static final String key_chat_inAudioSeekbarSelected = "chat_inAudioSeekbarSelected";
    public static final String key_chat_inAudioSelectedProgress = "chat_inAudioSelectedProgress";
    public static final String key_chat_inAudioTitleText = "chat_inAudioTitleText";
    public static final String key_chat_inBubble = "chat_inBubble";
    public static final String key_chat_inBubbleSelected = "chat_inBubbleSelected";
    public static final String key_chat_inBubbleShadow = "chat_inBubbleShadow";
    public static final String key_chat_inContactBackground = "chat_inContactBackground";
    public static final String key_chat_inContactIcon = "chat_inContactIcon";
    public static final String key_chat_inContactNameText = "chat_inContactNameText";
    public static final String key_chat_inContactPhoneSelectedText = "chat_inContactPhoneSelectedText";
    public static final String key_chat_inContactPhoneText = "chat_inContactPhoneText";
    public static final String key_chat_inFileBackground = "chat_inFileBackground";
    public static final String key_chat_inFileBackgroundSelected = "chat_inFileBackgroundSelected";
    public static final String key_chat_inFileIcon = "chat_inFileIcon";
    public static final String key_chat_inFileInfoSelectedText = "chat_inFileInfoSelectedText";
    public static final String key_chat_inFileInfoText = "chat_inFileInfoText";
    public static final String key_chat_inFileNameText = "chat_inFileNameText";
    public static final String key_chat_inFileProgress = "chat_inFileProgress";
    public static final String key_chat_inFileProgressSelected = "chat_inFileProgressSelected";
    public static final String key_chat_inFileSelectedIcon = "chat_inFileSelectedIcon";
    public static final String key_chat_inForwardedNameText = "chat_inForwardedNameText";
    public static final String key_chat_inGreenCall = "chat_inDownCall";
    public static final String key_chat_inInstant = "chat_inInstant";
    public static final String key_chat_inInstantSelected = "chat_inInstantSelected";
    public static final String key_chat_inLoader = "chat_inLoader";
    public static final String key_chat_inLoaderPhoto = "chat_inLoaderPhoto";
    public static final String key_chat_inLoaderPhotoIcon = "chat_inLoaderPhotoIcon";
    public static final String key_chat_inLoaderPhotoIconSelected = "chat_inLoaderPhotoIconSelected";
    public static final String key_chat_inLoaderPhotoSelected = "chat_inLoaderPhotoSelected";
    public static final String key_chat_inLoaderSelected = "chat_inLoaderSelected";
    public static final String key_chat_inLocationBackground = "chat_inLocationBackground";
    public static final String key_chat_inLocationIcon = "chat_inLocationIcon";
    public static final String key_chat_inMediaIcon = "chat_inMediaIcon";
    public static final String key_chat_inMediaIconSelected = "chat_inMediaIconSelected";
    public static final String key_chat_inMenu = "chat_inMenu";
    public static final String key_chat_inMenuSelected = "chat_inMenuSelected";
    public static final String key_chat_inPreviewInstantSelectedText = "chat_inPreviewInstantSelectedText";
    public static final String key_chat_inPreviewInstantText = "chat_inPreviewInstantText";
    public static final String key_chat_inPreviewLine = "chat_inPreviewLine";
    public static final String key_chat_inRedCall = "chat_inUpCall";
    public static final String key_chat_inReplyLine = "chat_inReplyLine";
    public static final String key_chat_inReplyMediaMessageSelectedText = "chat_inReplyMediaMessageSelectedText";
    public static final String key_chat_inReplyMediaMessageText = "chat_inReplyMediaMessageText";
    public static final String key_chat_inReplyMessageText = "chat_inReplyMessageText";
    public static final String key_chat_inReplyNameText = "chat_inReplyNameText";
    public static final String key_chat_inSentClock = "chat_inSentClock";
    public static final String key_chat_inSentClockSelected = "chat_inSentClockSelected";
    public static final String key_chat_inSiteNameText = "chat_inSiteNameText";
    public static final String key_chat_inTimeSelectedText = "chat_inTimeSelectedText";
    public static final String key_chat_inTimeText = "chat_inTimeText";
    public static final String key_chat_inVenueInfoSelectedText = "chat_inVenueInfoSelectedText";
    public static final String key_chat_inVenueInfoText = "chat_inVenueInfoText";
    public static final String key_chat_inViaBotNameText = "chat_inViaBotNameText";
    public static final String key_chat_inViews = "chat_inViews";
    public static final String key_chat_inViewsSelected = "chat_inViewsSelected";
    public static final String key_chat_inVoiceIcon = "chat_inVoiceIcon";
    public static final String key_chat_inVoiceSeekbar = "chat_inVoiceSeekbar";
    public static final String key_chat_inVoiceSeekbarFill = "chat_inVoiceSeekbarFill";
    public static final String key_chat_inVoiceSeekbarSelected = "chat_inVoiceSeekbarSelected";
    public static final String key_chat_inlineResultIcon = "chat_inlineResultIcon";
    public static final String key_chat_linkSelectBackground = "chat_linkSelectBackground";
    public static final String key_chat_lockIcon = "chat_lockIcon";
    public static final String key_chat_mediaBroadcast = "chat_mediaBroadcast";
    public static final String key_chat_mediaInfoText = "chat_mediaInfoText";
    public static final String key_chat_mediaLoaderPhoto = "chat_mediaLoaderPhoto";
    public static final String key_chat_mediaLoaderPhotoIcon = "chat_mediaLoaderPhotoIcon";
    public static final String key_chat_mediaLoaderPhotoIconSelected = "chat_mediaLoaderPhotoIconSelected";
    public static final String key_chat_mediaLoaderPhotoSelected = "chat_mediaLoaderPhotoSelected";
    public static final String key_chat_mediaMenu = "chat_mediaMenu";
    public static final String key_chat_mediaProgress = "chat_mediaProgress";
    public static final String key_chat_mediaSentCheck = "chat_mediaSentCheck";
    public static final String key_chat_mediaSentClock = "chat_mediaSentClock";
    public static final String key_chat_mediaTimeBackground = "chat_mediaTimeBackground";
    public static final String key_chat_mediaTimeText = "chat_mediaTimeText";
    public static final String key_chat_mediaViews = "chat_mediaViews";
    public static final String key_chat_messageLinkIn = "chat_messageLinkIn";
    public static final String key_chat_messageLinkOut = "chat_messageLinkOut";
    public static final String key_chat_messagePanelBackground = "chat_messagePanelBackground";
    public static final String key_chat_messagePanelCancelInlineBot = "chat_messagePanelCancelInlineBot";
    public static final String key_chat_messagePanelCursor = "chat_messagePanelCursor";
    public static final String key_chat_messagePanelHint = "chat_messagePanelHint";
    public static final String key_chat_messagePanelIcons = "chat_messagePanelIcons";
    public static final String key_chat_messagePanelMetionText = "chat_messagePanelMetionText";
    public static final String key_chat_messagePanelSend = "chat_messagePanelSend";
    public static final String key_chat_messagePanelSendPressed = "chat_messagePanelPressedSend";
    public static final String key_chat_messagePanelShadow = "chat_messagePanelShadow";
    public static final String key_chat_messagePanelText = "chat_messagePanelText";
    public static final String key_chat_messagePanelVideoFrame = "chat_messagePanelVideoFrame";
    public static final String key_chat_messagePanelVoiceBackground = "chat_messagePanelVoiceBackground";
    public static final String key_chat_messagePanelVoiceDelete = "chat_messagePanelVoiceDelete";
    public static final String key_chat_messagePanelVoiceDuration = "chat_messagePanelVoiceDuration";
    public static final String key_chat_messagePanelVoiceLock = "key_chat_messagePanelVoiceLock";
    public static final String key_chat_messagePanelVoiceLockBackground = "key_chat_messagePanelVoiceLockBackground";
    public static final String key_chat_messagePanelVoiceLockShadow = "key_chat_messagePanelVoiceLockShadow";
    public static final String key_chat_messagePanelVoicePressed = "chat_messagePanelVoicePressed";
    public static final String key_chat_messagePanelVoiceShadow = "chat_messagePanelVoiceShadow";
    public static final String key_chat_messageTextIn = "chat_messageTextIn";
    public static final String key_chat_messageTextOut = "chat_messageTextOut";
    public static final String key_chat_muteIcon = "chat_muteIcon";
    public static final String key_chat_outAudioCacheSeekbar = "chat_outAudioCacheSeekbar";
    public static final String key_chat_outAudioDurationSelectedText = "chat_outAudioDurationSelectedText";
    public static final String key_chat_outAudioDurationText = "chat_outAudioDurationText";
    public static final String key_chat_outAudioPerformerSelectedText = "chat_outAudioPerfomerSelectedText";
    public static final String key_chat_outAudioPerformerText = "chat_outAudioPerfomerText";
    public static final String key_chat_outAudioProgress = "chat_outAudioProgress";
    public static final String key_chat_outAudioSeekbar = "chat_outAudioSeekbar";
    public static final String key_chat_outAudioSeekbarFill = "chat_outAudioSeekbarFill";
    public static final String key_chat_outAudioSeekbarSelected = "chat_outAudioSeekbarSelected";
    public static final String key_chat_outAudioSelectedProgress = "chat_outAudioSelectedProgress";
    public static final String key_chat_outAudioTitleText = "chat_outAudioTitleText";
    public static final String key_chat_outBroadcast = "chat_outBroadcast";
    public static final String key_chat_outBubble = "chat_outBubble";
    public static final String key_chat_outBubbleSelected = "chat_outBubbleSelected";
    public static final String key_chat_outBubbleShadow = "chat_outBubbleShadow";
    public static final String key_chat_outContactBackground = "chat_outContactBackground";
    public static final String key_chat_outContactIcon = "chat_outContactIcon";
    public static final String key_chat_outContactNameText = "chat_outContactNameText";
    public static final String key_chat_outContactPhoneSelectedText = "chat_outContactPhoneSelectedText";
    public static final String key_chat_outContactPhoneText = "chat_outContactPhoneText";
    public static final String key_chat_outDocumentLoader = "chat_outDocumentLoader";
    public static final String key_chat_outDocumentLoaderSelected = "chat_outDocumentLoaderSelected";
    public static final String key_chat_outFileBackground = "chat_outFileBackground";
    public static final String key_chat_outFileBackgroundSelected = "chat_outFileBackgroundSelected";
    public static final String key_chat_outFileIcon = "chat_outFileIcon";
    public static final String key_chat_outFileInfoSelectedText = "chat_outFileInfoSelectedText";
    public static final String key_chat_outFileInfoText = "chat_outFileInfoText";
    public static final String key_chat_outFileNameText = "chat_outFileNameText";
    public static final String key_chat_outFileProgress = "chat_outFileProgress";
    public static final String key_chat_outFileProgressSelected = "chat_outFileProgressSelected";
    public static final String key_chat_outFileSelectedIcon = "chat_outFileSelectedIcon";
    public static final String key_chat_outForwardedNameText = "chat_outForwardedNameText";
    public static final String key_chat_outGreenCall = "chat_outUpCall";
    public static final String key_chat_outInstant = "chat_outInstant";
    public static final String key_chat_outInstantSelected = "chat_outInstantSelected";
    public static final String key_chat_outLoader = "chat_outLoader";
    public static final String key_chat_outLoaderPhoto = "chat_outLoaderPhoto";
    public static final String key_chat_outLoaderPhotoIcon = "chat_outLoaderPhotoIcon";
    public static final String key_chat_outLoaderPhotoIconSelected = "chat_outLoaderPhotoIconSelected";
    public static final String key_chat_outLoaderPhotoSelected = "chat_outLoaderPhotoSelected";
    public static final String key_chat_outLoaderSelected = "chat_outLoaderSelected";
    public static final String key_chat_outLocationBackground = "chat_outLocationBackground";
    public static final String key_chat_outLocationIcon = "chat_outLocationIcon";
    public static final String key_chat_outMediaBubbleShadow = "chat_outMediaBubbleShadow";
    public static final String key_chat_outMediaIcon = "chat_outMediaIcon";
    public static final String key_chat_outMediaIconSelected = "chat_outMediaIconSelected";
    public static final String key_chat_outMenu = "chat_outMenu";
    public static final String key_chat_outMenuSelected = "chat_outMenuSelected";
    public static final String key_chat_outPreviewInstantSelectedText = "chat_outPreviewInstantSelectedText";
    public static final String key_chat_outPreviewInstantText = "chat_outPreviewInstantText";
    public static final String key_chat_outPreviewLine = "chat_outPreviewLine";
    public static final String key_chat_outReplyLine = "chat_outReplyLine";
    public static final String key_chat_outReplyMediaMessageSelectedText = "chat_outReplyMediaMessageSelectedText";
    public static final String key_chat_outReplyMediaMessageText = "chat_outReplyMediaMessageText";
    public static final String key_chat_outReplyMessageText = "chat_outReplyMessageText";
    public static final String key_chat_outReplyNameText = "chat_outReplyNameText";
    public static final String key_chat_outSentCheck = "chat_outSentCheck";
    public static final String key_chat_outSentCheckRead = "chat_outSentCheckRead";
    public static final String key_chat_outSentCheckReadSelected = "chat_outSentCheckReadSelected";
    public static final String key_chat_outSentCheckSelected = "chat_outSentCheckSelected";
    public static final String key_chat_outSentClock = "chat_outSentClock";
    public static final String key_chat_outSentClockSelected = "chat_outSentClockSelected";
    public static final String key_chat_outSiteNameText = "chat_outSiteNameText";
    public static final String key_chat_outTimeSelectedText = "chat_outTimeSelectedText";
    public static final String key_chat_outTimeText = "chat_outTimeText";
    public static final String key_chat_outVenueInfoSelectedText = "chat_outVenueInfoSelectedText";
    public static final String key_chat_outVenueInfoText = "chat_outVenueInfoText";
    public static final String key_chat_outViaBotNameText = "chat_outViaBotNameText";
    public static final String key_chat_outViews = "chat_outViews";
    public static final String key_chat_outViewsSelected = "chat_outViewsSelected";
    public static final String key_chat_outVoiceIcon = "chat_outVoiceIcon";
    public static final String key_chat_outVoiceSeekbar = "chat_outVoiceSeekbar";
    public static final String key_chat_outVoiceSeekbarFill = "chat_outVoiceSeekbarFill";
    public static final String key_chat_outVoiceSeekbarSelected = "chat_outVoiceSeekbarSelected";
    public static final String key_chat_previewDurationText = "chat_previewDurationText";
    public static final String key_chat_previewGameText = "chat_previewGameText";
    public static final String key_chat_recordTime = "chat_recordTime";
    public static final String key_chat_recordVoiceCancel = "chat_recordVoiceCancel";
    public static final String key_chat_recordedVoiceBackground = "chat_recordedVoiceBackground";
    public static final String key_chat_recordedVoiceDot = "chat_recordedVoiceDot";
    public static final String key_chat_recordedVoicePlayPause = "chat_recordedVoicePlayPause";
    public static final String key_chat_recordedVoicePlayPausePressed = "chat_recordedVoicePlayPausePressed";
    public static final String key_chat_recordedVoiceProgress = "chat_recordedVoiceProgress";
    public static final String key_chat_recordedVoiceProgressInner = "chat_recordedVoiceProgressInner";
    public static final String key_chat_redpacketLinkServiceText = "chat_redpacketLinkServiceText";
    public static final String key_chat_redpacketServiceText = "chat_redpacketServiceText";
    public static final String key_chat_replyBackground = "chat_replyBackground";
    public static final String key_chat_replyPanelClose = "chat_replyPanelClose";
    public static final String key_chat_replyPanelIcons = "chat_replyPanelIcons";
    public static final String key_chat_replyPanelLine = "chat_replyPanelLine";
    public static final String key_chat_replyPanelMessage = "chat_replyPanelMessage";
    public static final String key_chat_replyPanelName = "chat_replyPanelName";
    public static final String key_chat_reportSpam = "chat_reportSpam";
    public static final String key_chat_searchPanelIcons = "chat_searchPanelIcons";
    public static final String key_chat_searchPanelText = "chat_searchPanelText";
    public static final String key_chat_secretChatStatusText = "chat_secretChatStatusText";
    public static final String key_chat_secretTimeText = "chat_secretTimeText";
    public static final String key_chat_secretTimerBackground = "chat_secretTimerBackground";
    public static final String key_chat_secretTimerText = "chat_secretTimerText";
    public static final String key_chat_selectedBackground = "chat_selectedBackground";
    public static final String key_chat_sentError = "chat_sentError";
    public static final String key_chat_sentErrorIcon = "chat_sentErrorIcon";
    public static final String key_chat_serviceBackground = "chat_serviceBackground";
    public static final String key_chat_serviceBackgroundSelected = "chat_serviceBackgroundSelected";
    public static final String key_chat_serviceIcon = "chat_serviceIcon";
    public static final String key_chat_serviceLink = "chat_serviceLink";
    public static final String key_chat_serviceText = "chat_serviceText";
    public static final String key_chat_shareBackground = "chat_shareBackground";
    public static final String key_chat_shareBackgroundSelected = "chat_shareBackgroundSelected";
    public static final String key_chat_status = "chat_status";
    public static final String key_chat_stickerNameText = "chat_stickerNameText";
    public static final String key_chat_stickerReplyLine = "chat_stickerReplyLine";
    public static final String key_chat_stickerReplyMessageText = "chat_stickerReplyMessageText";
    public static final String key_chat_stickerReplyNameText = "chat_stickerReplyNameText";
    public static final String key_chat_stickerViaBotNameText = "chat_stickerViaBotNameText";
    public static final String key_chat_stickersHintPanel = "chat_stickersHintPanel";
    public static final String key_chat_textSelectBackground = "chat_textSelectBackground";
    public static final String key_chat_topPanelBackground = "chat_topPanelBackground";
    public static final String key_chat_topPanelClose = "chat_topPanelClose";
    public static final String key_chat_topPanelLine = "chat_topPanelLine";
    public static final String key_chat_topPanelMessage = "chat_topPanelMessage";
    public static final String key_chat_topPanelTitle = "chat_topPanelTitle";
    public static final String key_chat_unreadMessagesStartArrowIcon = "chat_unreadMessagesStartArrowIcon";
    public static final String key_chat_unreadMessagesStartBackground = "chat_unreadMessagesStartBackground";
    public static final String key_chat_unreadMessagesStartText = "chat_unreadMessagesStartText";
    public static final String key_chat_wallpaper = "chat_wallpaper";
    public static final String key_chat_wallpaper_gradient_to = "chat_wallpaper_gradient_to";
    public static final String key_chats_actionBackground = "chats_actionBackground";
    public static final String key_chats_actionIcon = "chats_actionIcon";
    public static final String key_chats_actionMessage = "chats_actionMessage";
    public static final String key_chats_actionPressedBackground = "chats_actionPressedBackground";
    public static final String key_chats_actionUnreadBackground = "chats_actionUnreadBackground";
    public static final String key_chats_actionUnreadIcon = "chats_actionUnreadIcon";
    public static final String key_chats_actionUnreadPressedBackground = "chats_actionUnreadPressedBackground";
    public static final String key_chats_archiveBackground = "chats_archiveBackground";
    public static final String key_chats_archiveIcon = "chats_archiveIcon";
    public static final String key_chats_archivePinBackground = "chats_archivePinBackground";
    public static final String key_chats_archiveText = "chats_archiveText";
    public static final String key_chats_attachMessage = "chats_attachMessage";
    public static final String key_chats_date = "chats_date";
    public static final String key_chats_draft = "chats_draft";
    public static final String key_chats_mentionIcon = "chats_mentionIcon";
    public static final String key_chats_menuBackground = "chats_menuBackground";
    public static final String key_chats_menuCloud = "chats_menuCloud";
    public static final String key_chats_menuCloudBackgroundCats = "chats_menuCloudBackgroundCats";
    public static final String key_chats_menuItemCheck = "chats_menuItemCheck";
    public static final String key_chats_menuItemIcon = "chats_menuItemIcon";
    public static final String key_chats_menuItemText = "chats_menuItemText";
    public static final String key_chats_menuName = "chats_menuName";
    public static final String key_chats_menuPhone = "chats_menuPhone";
    public static final String key_chats_menuPhoneCats = "chats_menuPhoneCats";
    public static final String key_chats_menuTopBackground = "chats_menuTopBackground";
    public static final String key_chats_menuTopBackgroundCats = "chats_menuTopBackgroundCats";
    public static final String key_chats_menuTopShadow = "chats_menuTopShadow";
    public static final String key_chats_menuTopShadowCats = "chats_menuTopShadowCats";
    public static final String key_chats_message = "chats_message";
    public static final String key_chats_messageArchived = "chats_messageArchived";
    public static final String key_chats_message_threeLines = "chats_message_threeLines";
    public static final String key_chats_muteIcon = "chats_muteIcon";
    public static final String key_chats_name = "chats_name";
    public static final String key_chats_nameArchived = "chats_nameArchived";
    public static final String key_chats_nameIcon = "chats_nameIcon";
    public static final String key_chats_nameMessage = "chats_nameMessage";
    public static final String key_chats_nameMessageArchived = "chats_nameMessageArchived";
    public static final String key_chats_nameMessageArchived_threeLines = "chats_nameMessageArchived_threeLines";
    public static final String key_chats_nameMessage_threeLines = "chats_nameMessage_threeLines";
    public static final String key_chats_onlineCircle = "chats_onlineCircle";
    public static final String key_chats_pinnedIcon = "chats_pinnedIcon";
    public static final String key_chats_pinnedOverlay = "chats_pinnedOverlay";
    public static final String key_chats_secretIcon = "chats_secretIcon";
    public static final String key_chats_secretName = "chats_secretName";
    public static final String key_chats_sentCheck = "chats_sentCheck";
    public static final String key_chats_sentClock = "chats_sentClock";
    public static final String key_chats_sentError = "chats_sentError";
    public static final String key_chats_sentErrorIcon = "chats_sentErrorIcon";
    public static final String key_chats_sentReadCheck = "chats_sentReadCheck";
    public static final String key_chats_sersviceBackground = "chats_sersviceBackground";
    public static final String key_chats_tabletSelectedOverlay = "chats_tabletSelectedOverlay";
    public static final String key_chats_unreadCounter = "chats_unreadCounter";
    public static final String key_chats_unreadCounterMuted = "chats_unreadCounterMuted";
    public static final String key_chats_unreadCounterText = "chats_unreadCounterText";
    public static final String key_chats_verifiedBackground = "chats_verifiedBackground";
    public static final String key_chats_verifiedCheck = "chats_verifiedCheck";
    public static final String key_checkbox = "checkbox";
    public static final String key_checkboxCheck = "checkboxCheck";
    public static final String key_checkboxDisabled = "checkboxDisabled";
    public static final String key_checkboxSquareBackground = "checkboxSquareBackground";
    public static final String key_checkboxSquareCheck = "checkboxSquareCheck";
    public static final String key_checkboxSquareDisabled = "checkboxSquareDisabled";
    public static final String key_checkboxSquareUnchecked = "checkboxSquareUnchecked";
    public static final String key_color_42B71E = "key_color_42B71E";
    public static final String key_contacts_inviteBackground = "contacts_inviteBackground";
    public static final String key_contacts_inviteText = "contacts_inviteText";
    public static final String key_contacts_userCellDeleteBackground = "contacts_userCellDeleteBackground";
    public static final String key_contacts_userCellDeleteText = "contacts_userCellDeleteText";
    public static final String key_contextProgressInner1 = "contextProgressInner1";
    public static final String key_contextProgressInner2 = "contextProgressInner2";
    public static final String key_contextProgressInner3 = "contextProgressInner3";
    public static final String key_contextProgressInner4 = "contextProgressInner4";
    public static final String key_contextProgressOuter1 = "contextProgressOuter1";
    public static final String key_contextProgressOuter2 = "contextProgressOuter2";
    public static final String key_contextProgressOuter3 = "contextProgressOuter3";
    public static final String key_contextProgressOuter4 = "contextProgressOuter4";
    public static final String key_dialogBackground = "dialogBackground";
    public static final String key_dialogBackgroundGray = "dialogBackgroundGray";
    public static final String key_dialogBadgeBackground = "dialogBadgeBackground";
    public static final String key_dialogBadgeText = "dialogBadgeText";
    public static final String key_dialogButton = "dialogButton";
    public static final String key_dialogButtonSelector = "dialogButtonSelector";
    public static final String key_dialogCameraIcon = "dialogCameraIcon";
    public static final String key_dialogCheckboxSquareBackground = "dialogCheckboxSquareBackground";
    public static final String key_dialogCheckboxSquareCheck = "dialogCheckboxSquareCheck";
    public static final String key_dialogCheckboxSquareDisabled = "dialogCheckboxSquareDisabled";
    public static final String key_dialogCheckboxSquareUnchecked = "dialogCheckboxSquareUnchecked";
    public static final String key_dialogFloatingButton = "dialogFloatingButton";
    public static final String key_dialogFloatingButtonPressed = "dialogFloatingButtonPressed";
    public static final String key_dialogFloatingIcon = "dialogFloatingIcon";
    public static final String key_dialogGrayLine = "dialogGrayLine";
    public static final String key_dialogIcon = "dialogIcon";
    public static final String key_dialogInputField = "dialogInputField";
    public static final String key_dialogInputFieldActivated = "dialogInputFieldActivated";
    public static final String key_dialogLineProgress = "dialogLineProgress";
    public static final String key_dialogLineProgressBackground = "dialogLineProgressBackground";
    public static final String key_dialogLinkSelection = "dialogLinkSelection";
    public static final String key_dialogProgressCircle = "dialogProgressCircle";
    public static final String key_dialogRadioBackground = "dialogRadioBackground";
    public static final String key_dialogRadioBackgroundChecked = "dialogRadioBackgroundChecked";
    public static final String key_dialogRedIcon = "dialogRedIcon";
    public static final String key_dialogRoundCheckBox = "dialogRoundCheckBox";
    public static final String key_dialogRoundCheckBoxCheck = "dialogRoundCheckBoxCheck";
    public static final String key_dialogScrollGlow = "dialogScrollGlow";
    public static final String key_dialogSearchBackground = "dialogSearchBackground";
    public static final String key_dialogSearchHint = "dialogSearchHint";
    public static final String key_dialogSearchIcon = "dialogSearchIcon";
    public static final String key_dialogSearchText = "dialogSearchText";
    public static final String key_dialogShadowLine = "dialogShadowLine";
    public static final String key_dialogTextBlack = "dialogTextBlack";
    public static final String key_dialogTextBlue = "dialogTextBlue";
    public static final String key_dialogTextBlue2 = "dialogTextBlue2";
    public static final String key_dialogTextBlue3 = "dialogTextBlue3";
    public static final String key_dialogTextBlue4 = "dialogTextBlue4";
    public static final String key_dialogTextGray = "dialogTextGray";
    public static final String key_dialogTextGray2 = "dialogTextGray2";
    public static final String key_dialogTextGray3 = "dialogTextGray3";
    public static final String key_dialogTextGray4 = "dialogTextGray4";
    public static final String key_dialogTextHint = "dialogTextHint";
    public static final String key_dialogTextLink = "dialogTextLink";
    public static final String key_dialogTextRed = "dialogTextRed";
    public static final String key_dialogTextRed2 = "dialogTextRed2";
    public static final String key_dialogTopBackground = "dialogTopBackground";
    public static final String key_dialog_inlineProgress = "dialog_inlineProgress";
    public static final String key_dialog_inlineProgressBackground = "dialog_inlineProgressBackground";
    public static final String key_dialog_liveLocationProgress = "dialog_liveLocationProgress";
    public static final String key_divider = "divider";
    public static final String key_emptyListPlaceholder = "emptyListPlaceholder";
    public static final String key_fastScrollActive = "fastScrollActive";
    public static final String key_fastScrollInactive = "fastScrollInactive";
    public static final String key_fastScrollText = "fastScrollText";
    public static final String key_featuredStickers_addButton = "featuredStickers_addButton";
    public static final String key_featuredStickers_addButtonPressed = "featuredStickers_addButtonPressed";
    public static final String key_featuredStickers_addedIcon = "featuredStickers_addedIcon";
    public static final String key_featuredStickers_buttonProgress = "featuredStickers_buttonProgress";
    public static final String key_featuredStickers_buttonText = "featuredStickers_buttonText";
    public static final String key_featuredStickers_delButton = "featuredStickers_delButton";
    public static final String key_featuredStickers_delButtonPressed = "featuredStickers_delButtonPressed";
    public static final String key_featuredStickers_unread = "featuredStickers_unread";
    public static final String key_files_folderIcon = "files_folderIcon";
    public static final String key_files_folderIconBackground = "files_folderIconBackground";
    public static final String key_files_iconText = "files_iconText";
    public static final String key_gradient1Location1 = "key_gradient1Location1";
    public static final String key_gradient1Location2 = "key_gradient1Location2";
    public static final String key_gradient2Location1 = "key_gradient2Location1";
    public static final String key_gradient2Location2 = "key_gradient2Location2";
    public static final String key_graySection = "graySection";
    public static final String key_graySectionText = "key_graySectionText";
    public static final String key_groupcreate_cursor = "groupcreate_cursor";
    public static final String key_groupcreate_hintText = "groupcreate_hintText";
    public static final String key_groupcreate_sectionShadow = "groupcreate_sectionShadow";
    public static final String key_groupcreate_sectionText = "groupcreate_sectionText";
    public static final String key_groupcreate_spanBackground = "groupcreate_spanBackground";
    public static final String key_groupcreate_spanDelete = "groupcreate_spanDelete";
    public static final String key_groupcreate_spanText = "groupcreate_spanText";
    public static final String key_inappPlayerBackground = "inappPlayerBackground";
    public static final String key_inappPlayerClose = "inappPlayerClose";
    public static final String key_inappPlayerPerformer = "inappPlayerPerformer";
    public static final String key_inappPlayerPlayPause = "inappPlayerPlayPause";
    public static final String key_inappPlayerTitle = "inappPlayerTitle";
    public static final String key_listSelector = "listSelectorSDK21";
    public static final String key_list_decorationBackground = "list_decorationBackground";
    public static final String key_list_decorationTextColor = "list_decorationText";
    public static final String key_live_mute = "live_mute";
    public static final String key_live_unmute = "live_unmute";
    public static final String key_location_liveLocationProgress = "location_liveLocationProgress";
    public static final String key_location_placeLocationBackground = "location_placeLocationBackground";
    public static final String key_location_sendLiveLocationBackground = "location_sendLiveLocationBackground";
    public static final String key_location_sendLiveLocationIcon = "location_sendLiveLocationIcon";
    public static final String key_location_sendLocationBackground = "location_sendLocationBackground";
    public static final String key_location_sendLocationIcon = "location_sendLocationIcon";
    public static final String key_login_progressInner = "login_progressInner";
    public static final String key_login_progressOuter = "login_progressOuter";
    public static final String key_musicPicker_buttonBackground = "musicPicker_buttonBackground";
    public static final String key_musicPicker_buttonIcon = "musicPicker_buttonIcon";
    public static final String key_musicPicker_checkbox = "musicPicker_checkbox";
    public static final String key_musicPicker_checkboxCheck = "musicPicker_checkboxCheck";
    public static final String key_neutralActive = "key_neutralActive";
    public static final String key_neutralBody = "key_neutralBody";
    public static final String key_neutralDark = "key_neutralDark";
    public static final String key_neutralDisabled = "key_neutralDisabled";
    public static final String key_neutralLine = "key_neutralLine";
    public static final String key_neutralSecondaryBG = "key_neutralSecondaryBG";
    public static final String key_neutralWeak = "key_neutralWeak";
    public static final String key_neutralWhite = "key_neutralWhite";
    public static final String key_pageBackgroundColor = "key_pageBackgroundColor";
    public static final String key_passport_authorizeBackground = "passport_authorizeBackground";
    public static final String key_passport_authorizeBackgroundSelected = "passport_authorizeBackgroundSelected";
    public static final String key_passport_authorizeText = "passport_authorizeText";
    public static final String key_picker_badge = "picker_badge";
    public static final String key_picker_badgeText = "picker_badgeText";
    public static final String key_picker_disabledButton = "picker_disabledButton";
    public static final String key_picker_enabledButton = "picker_enabledButton";
    public static final String key_player_actionBar = "player_actionBar";
    public static final String key_player_actionBarItems = "player_actionBarItems";
    public static final String key_player_actionBarSelector = "player_actionBarSelector";
    public static final String key_player_actionBarSubtitle = "player_actionBarSubtitle";
    public static final String key_player_actionBarTitle = "player_actionBarTitle";
    public static final String key_player_actionBarTop = "player_actionBarTop";
    public static final String key_player_background = "player_background";
    public static final String key_player_button = "player_button";
    public static final String key_player_buttonActive = "player_buttonActive";
    public static final String key_player_placeholder = "player_placeholder";
    public static final String key_player_placeholderBackground = "player_placeholderBackground";
    public static final String key_player_progress = "player_progress";
    public static final String key_player_progressBackground = "player_progressBackground";
    public static final String key_player_progressCachedBackground = "key_player_progressCachedBackground";
    public static final String key_player_time = "player_time";
    public static final String key_profileBottomBackgroundGray = "profileBottomBackgroundGray";
    public static final String key_profileBtnBackgroundBlue = "profileBtnBackgroundBlue";
    public static final String key_profileBtnBackgroundGray = "profileBtnBackgroundGray";
    public static final String key_profile_actionBackground = "profile_actionBackground";
    public static final String key_profile_actionIcon = "profile_actionIcon";
    public static final String key_profile_actionPressedBackground = "profile_actionPressedBackground";
    public static final String key_profile_creatorIcon = "profile_creatorIcon";
    public static final String key_profile_status = "profile_status";
    public static final String key_profile_title = "profile_title";
    public static final String key_profile_verifiedBackground = "profile_verifiedBackground";
    public static final String key_profile_verifiedCheck = "profile_verifiedCheck";
    public static final String key_progressCircle = "progressCircle";
    public static final String key_radioBackground = "radioBackground";
    public static final String key_radioBackgroundChecked = "radioBackgroundChecked";
    public static final String key_returnToCallBackground = "returnToCallBackground";
    public static final String key_returnToCallText = "returnToCallText";
    public static final String key_searchview_solidColor = "searchview_soldColor";
    public static final String key_searchview_strokeColor = "searchview_strokeColor";
    public static final String key_sessions_devicesImage = "sessions_devicesImage";
    public static final String key_shadowColor = "key_shadowColor";
    public static final String key_sharedMedia_actionMode = "sharedMedia_actionMode";
    public static final String key_sharedMedia_linkPlaceholder = "sharedMedia_linkPlaceholder";
    public static final String key_sharedMedia_linkPlaceholderText = "sharedMedia_linkPlaceholderText";
    public static final String key_sharedMedia_photoPlaceholder = "sharedMedia_photoPlaceholder";
    public static final String key_sharedMedia_startStopLoadIcon = "sharedMedia_startStopLoadIcon";
    public static final String key_sheet_other = "key_sheet_other";
    public static final String key_sheet_scrollUp = "key_sheet_scrollUp";
    public static final String key_sidebar_textDefaultColor = "sidebar_textDefaultColor";
    public static final String key_sidebar_textSelectedColor = "sidebar_textSelectedColor";
    public static final String key_stickers_menu = "stickers_menu";
    public static final String key_stickers_menuSelector = "stickers_menuSelector";
    public static final String key_switch2Track = "switch2Track";
    public static final String key_switch2TrackChecked = "switch2TrackChecked";
    public static final String key_switchTrack = "switchTrack";
    public static final String key_switchTrackBlue = "switchTrackBlue";
    public static final String key_switchTrackBlueChecked = "switchTrackBlueChecked";
    public static final String key_switchTrackBlueSelector = "switchTrackBlueSelector";
    public static final String key_switchTrackBlueSelectorChecked = "switchTrackBlueSelectorChecked";
    public static final String key_switchTrackBlueThumb = "switchTrackBlueThumb";
    public static final String key_switchTrackBlueThumbChecked = "switchTrackBlueThumbChecked";
    public static final String key_switchTrackChecked = "switchTrackChecked";
    public static final String key_themeCheckBoxChecked = "themeCheckBoxChecked";
    public static final String key_themeCheckBoxDisabled = "themeCheckBoxDisabled";
    public static final String key_themeCheckBoxUnchecked = "themeCheckBoxUnchecked";
    public static final String key_undo_background = "undo_background";
    public static final String key_undo_cancelColor = "undo_cancelColor";
    public static final String key_undo_infoColor = "undo_infoColor";
    public static final String key_walletDefaultBackground = "walletDefaultBackground";
    public static final String key_walletHoloBlueLight = "walletHoloBlueLight";
    public static final String key_windowBackgroundCheckText = "windowBackgroundCheckText";
    public static final String key_windowBackgroundChecked = "windowBackgroundChecked";
    public static final String key_windowBackgroundGray = "windowBackgroundGray";
    public static final String key_windowBackgroundGrayShadow = "windowBackgroundGrayShadow";
    public static final String key_windowBackgroundGrayText = "window_backgroundGrayText";
    public static final String key_windowBackgroundUnchecked = "windowBackgroundUnchecked";
    public static final String key_windowBackgroundValueText1 = "window_backgroundValueText1";
    public static final String key_windowBackgroundWhite = "windowBackgroundWhite";
    public static final String key_windowBackgroundWhiteBlackText = "windowBackgroundWhiteBlackText";
    public static final String key_windowBackgroundWhiteBlueButton = "windowBackgroundWhiteBlueButton";
    public static final String key_windowBackgroundWhiteBlueHeader = "windowBackgroundWhiteBlueHeader";
    public static final String key_windowBackgroundWhiteBlueIcon = "windowBackgroundWhiteBlueIcon";
    public static final String key_windowBackgroundWhiteBlueText = "windowBackgroundWhiteBlueText";
    public static final String key_windowBackgroundWhiteBlueText2 = "windowBackgroundWhiteBlueText2";
    public static final String key_windowBackgroundWhiteBlueText3 = "windowBackgroundWhiteBlueText3";
    public static final String key_windowBackgroundWhiteBlueText4 = "windowBackgroundWhiteBlueText4";
    public static final String key_windowBackgroundWhiteBlueText5 = "windowBackgroundWhiteBlueText5";
    public static final String key_windowBackgroundWhiteBlueText6 = "windowBackgroundWhiteBlueText6";
    public static final String key_windowBackgroundWhiteBlueText7 = "windowBackgroundWhiteBlueText7";
    public static final String key_windowBackgroundWhiteGrayIcon = "windowBackgroundWhiteGrayIcon";
    public static final String key_windowBackgroundWhiteGrayLine = "windowBackgroundWhiteGrayLine";
    public static final String key_windowBackgroundWhiteGrayText = "windowBackgroundWhiteGrayText";
    public static final String key_windowBackgroundWhiteGrayText2 = "windowBackgroundWhiteGrayText2";
    public static final String key_windowBackgroundWhiteGrayText3 = "windowBackgroundWhiteGrayText3";
    public static final String key_windowBackgroundWhiteGrayText4 = "windowBackgroundWhiteGrayText4";
    public static final String key_windowBackgroundWhiteGrayText5 = "windowBackgroundWhiteGrayText5";
    public static final String key_windowBackgroundWhiteGrayText6 = "windowBackgroundWhiteGrayText6";
    public static final String key_windowBackgroundWhiteGrayText7 = "windowBackgroundWhiteGrayText7";
    public static final String key_windowBackgroundWhiteGrayText8 = "windowBackgroundWhiteGrayText8";
    public static final String key_windowBackgroundWhiteGreenText = "windowBackgroundWhiteGreenText";
    public static final String key_windowBackgroundWhiteGreenText2 = "windowBackgroundWhiteGreenText2";
    public static final String key_windowBackgroundWhiteHintText = "windowBackgroundWhiteHintText";
    public static final String key_windowBackgroundWhiteInputField = "windowBackgroundWhiteInputField";
    public static final String key_windowBackgroundWhiteInputFieldActivated = "windowBackgroundWhiteInputFieldActivated";
    public static final String key_windowBackgroundWhiteLinkSelection = "windowBackgroundWhiteLinkSelection";
    public static final String key_windowBackgroundWhiteLinkText = "windowBackgroundWhiteLinkText";
    public static final String key_windowBackgroundWhiteRedText = "windowBackgroundWhiteRedText";
    public static final String key_windowBackgroundWhiteRedText2 = "windowBackgroundWhiteRedText2";
    public static final String key_windowBackgroundWhiteRedText3 = "windowBackgroundWhiteRedText3";
    public static final String key_windowBackgroundWhiteRedText4 = "windowBackgroundWhiteRedText4";
    public static final String key_windowBackgroundWhiteRedText5 = "windowBackgroundWhiteRedText5";
    public static final String key_windowBackgroundWhiteRedText6 = "windowBackgroundWhiteRedText6";
    public static final String key_windowBackgroundWhiteValueText = "windowBackgroundWhiteValueText";
    private static long lastHolidayCheckTime = 0;
    private static int lastLoadingCurrentThemeTime = 0;
    private static int lastLoadingThemesTime = 0;
    private static long lastThemeSwitchTime = 0;
    private static Sensor lightSensor = null;
    private static boolean lightSensorRegistered = false;
    public static Paint linkSelectionPaint = null;
    public static Drawable listSelector = null;
    private static int loadingCurrentTheme = 0;
    private static boolean loadingRemoteThemes = false;
    public static Drawable moveUpDrawable = null;
    private static ArrayList<ThemeInfo> otherThemes = null;
    private static ThemeInfo previousTheme = null;
    public static TextPaint profile_aboutTextPaint = null;
    public static Drawable profile_verifiedCheckDrawable = null;
    public static Drawable profile_verifiedDrawable = null;
    private static int remoteThemesHash = 0;
    public static int selectedAutoNightType = 0;
    private static int selectedColor = 0;
    private static SensorManager sensorManager = null;
    private static int serviceMessage2Color = 0;
    private static int serviceMessageColor = 0;
    public static int serviceMessageColorBackup = 0;
    private static int serviceSelectedMessage2Color = 0;
    private static int serviceSelectedMessageColor = 0;
    public static int serviceSelectedMessageColorBackup = 0;
    private static boolean switchDayRunnableScheduled = false;
    private static boolean switchNightRunnableScheduled = false;
    private static boolean switchingNightTheme = false;
    private static Drawable themedWallpaper = null;
    private static int themedWallpaperFileOffset = 0;
    private static String themedWallpaperLink = null;
    public static ArrayList<ThemeInfo> themes = null;
    private static HashMap<String, ThemeInfo> themesDict = null;
    public static final int value_WalletPageBlueTextColor = -16744193;
    public static final int value_accentBlue = -15306762;
    public static final int value_accentError = -1490366;
    public static final int value_accentOrange = -1273334;
    public static final int value_accentSafe = -8664113;
    public static final int value_accentSuccess = -13844375;
    public static final int value_accentWarning = -143551;
    public static final int value_blackAlpha30 = -1291845632;
    public static final int value_blackAlpha70 = 1291845632;
    public static final int value_blackAlpha80 = 855638016;
    public static final int value_brandBG = -2959879;
    public static final int value_brandDark = -16770429;
    public static final int value_brandDarkMode = -13148161;
    public static final int value_brandDefault = -16765469;
    public static final int value_brandLight = -7888897;
    public static final int value_gradient1Location1 = -2959879;
    public static final int value_gradient1Location2 = -13879327;
    public static final int value_gradient2Location1 = -1270017;
    public static final int value_gradient2Location2 = -10539286;
    public static final int value_neutralActive = -15787992;
    public static final int value_neutralBody = -14996664;
    public static final int value_neutralDark = -15392717;
    public static final int value_neutralDisabled = -5392963;
    public static final int value_neutralLine = -1184275;
    public static final int value_neutralSecondaryBG = -526340;
    public static final int value_neutralWeak = -5987164;
    public static final int value_neutralWhite = -1;
    public static final int value_pageBackgroundColor = -526345;
    public static final int value_shadowColor = -184549376;
    private static Drawable wallpaper;
    private static final Object sync = new Object();
    private static final Object wallpaperSync = new Object();
    private static float lastBrightnessValue = 1.0f;
    private static Runnable switchDayBrightnessRunnable = new Runnable() { // from class: im.uwrkaxlmjj.ui.actionbar.Theme.1
        @Override // java.lang.Runnable
        public void run() {
            boolean unused = Theme.switchDayRunnableScheduled = false;
            Theme.applyDayNightThemeMaybe(false);
        }
    };
    private static Runnable switchNightBrightnessRunnable = new Runnable() { // from class: im.uwrkaxlmjj.ui.actionbar.Theme.2
        @Override // java.lang.Runnable
        public void run() {
            boolean unused = Theme.switchNightRunnableScheduled = false;
            Theme.applyDayNightThemeMaybe(true);
        }
    };
    private static Paint maskPaint = new Paint(1);
    public static Drawable[] chat_attachButtonDrawables = new Drawable[6];
    public static Drawable[] chat_locationDrawable = new Drawable[2];
    public static Drawable[] chat_contactDrawable = new Drawable[2];
    public static Drawable[] chat_cornerOuter = new Drawable[4];
    public static Drawable[] chat_cornerInner = new Drawable[4];
    public static Drawable[][] chat_fileStatesDrawable = (Drawable[][]) Array.newInstance((Class<?>) Drawable.class, 10, 2);
    public static CombinedDrawable[][] chat_fileMiniStatesDrawable = (CombinedDrawable[][]) Array.newInstance((Class<?>) CombinedDrawable.class, 6, 2);
    public static Drawable[][] chat_photoStatesDrawables = (Drawable[][]) Array.newInstance((Class<?>) Drawable.class, 13, 2);
    public static final String key_avatar_backgroundRed = "avatar_backgroundRed";
    public static final String key_avatar_backgroundOrange = "avatar_backgroundOrange";
    public static final String key_avatar_backgroundViolet = "avatar_backgroundViolet";
    public static final String key_avatar_backgroundGreen = "avatar_backgroundGreen";
    public static final String key_avatar_backgroundCyan = "avatar_backgroundCyan";
    public static final String key_avatar_backgroundBlue = "avatar_backgroundBlue";
    public static final String key_avatar_backgroundPink = "avatar_backgroundPink";
    public static String[] keys_avatar_background = {key_avatar_backgroundRed, key_avatar_backgroundOrange, key_avatar_backgroundViolet, key_avatar_backgroundGreen, key_avatar_backgroundCyan, key_avatar_backgroundBlue, key_avatar_backgroundPink};
    public static final String key_avatar_nameInMessageRed = "avatar_nameInMessageRed";
    public static final String key_avatar_nameInMessageOrange = "avatar_nameInMessageOrange";
    public static final String key_avatar_nameInMessageViolet = "avatar_nameInMessageViolet";
    public static final String key_avatar_nameInMessageGreen = "avatar_nameInMessageGreen";
    public static final String key_avatar_nameInMessageCyan = "avatar_nameInMessageCyan";
    public static final String key_avatar_nameInMessageBlue = "avatar_nameInMessageBlue";
    public static final String key_avatar_nameInMessagePink = "avatar_nameInMessagePink";
    public static String[] keys_avatar_nameInMessage = {key_avatar_nameInMessageRed, key_avatar_nameInMessageOrange, key_avatar_nameInMessageViolet, key_avatar_nameInMessageGreen, key_avatar_nameInMessageCyan, key_avatar_nameInMessageBlue, key_avatar_nameInMessagePink};
    private static HashMap<String, Integer> defaultColors = new HashMap<>();
    private static HashMap<String, String> fallbackKeys = new HashMap<>();
    private static HashSet<String> themeAccentExclusionKeys = new HashSet<>();
    private static float[] hsv = new float[3];

    public static class ThemeInfo implements NotificationCenter.NotificationCenterDelegate {
        public int accentBaseColor;
        final float[] accentBaseColorHsv;
        public int accentColor;
        final float[] accentColorHsv;
        public int[] accentColorOptions;
        public int account;
        public String assetName;
        public boolean badWallpaper;
        public TLRPC.TL_theme info;
        public boolean isBlured;
        public boolean isMotion;
        public boolean loaded;
        public String name;
        public String pathToFile;
        public String pathToWallpaper;
        public int previewBackgroundColor;
        public int previewBackgroundGradientColor;
        public int previewInColor;
        public int previewOutColor;
        public boolean previewParsed;
        public int previewWallpaperOffset;
        public String slug;
        public int sortIndex;
        public boolean themeLoaded;
        public TLRPC.InputFile uploadedFile;
        public TLRPC.InputFile uploadedThumb;
        public String uploadingFile;
        public String uploadingThumb;

        ThemeInfo() {
            this.loaded = true;
            this.themeLoaded = true;
            this.accentBaseColorHsv = new float[3];
            this.accentColorHsv = new float[3];
        }

        public ThemeInfo(ThemeInfo other) {
            this.loaded = true;
            this.themeLoaded = true;
            float[] fArr = new float[3];
            this.accentBaseColorHsv = fArr;
            this.accentColorHsv = new float[3];
            this.name = other.name;
            this.pathToFile = other.pathToFile;
            this.assetName = other.assetName;
            this.sortIndex = other.sortIndex;
            this.accentColorOptions = other.accentColorOptions;
            int i = other.accentBaseColor;
            this.accentBaseColor = i;
            this.accentColor = other.accentColor;
            this.info = other.info;
            this.loaded = other.loaded;
            this.uploadingThumb = other.uploadingThumb;
            this.uploadingFile = other.uploadingFile;
            this.uploadedThumb = other.uploadedThumb;
            this.uploadedFile = other.uploadedFile;
            this.account = other.account;
            this.pathToWallpaper = other.pathToWallpaper;
            this.slug = other.slug;
            this.badWallpaper = other.badWallpaper;
            this.isBlured = other.isBlured;
            this.isMotion = other.isMotion;
            this.previewBackgroundColor = other.previewBackgroundColor;
            this.previewBackgroundGradientColor = other.previewBackgroundGradientColor;
            this.previewWallpaperOffset = other.previewWallpaperOffset;
            this.previewInColor = other.previewInColor;
            this.previewOutColor = other.previewOutColor;
            this.previewParsed = other.previewParsed;
            this.themeLoaded = other.themeLoaded;
            Color.colorToHSV(i, fArr);
            Color.colorToHSV(this.accentColor, this.accentColorHsv);
        }

        JSONObject getSaveJson() {
            try {
                JSONObject jsonObject = new JSONObject();
                jsonObject.put("name", this.name);
                jsonObject.put("path", this.pathToFile);
                jsonObject.put("account", this.account);
                if (this.info != null) {
                    SerializedData data = new SerializedData(this.info.getObjectSize());
                    this.info.serializeToStream(data);
                    jsonObject.put("info", Utilities.bytesToHex(data.toByteArray()));
                }
                jsonObject.put("loaded", this.loaded);
                return jsonObject;
            } catch (Exception e) {
                FileLog.e(e);
                return null;
            }
        }

        public String getName() {
            if ("Default".equals(this.name)) {
                return LocaleController.getString("Default", R.string.Default);
            }
            if ("Blue".equals(this.name)) {
                return LocaleController.getString("ThemeBlue", R.string.ThemeBlue);
            }
            if ("Dark Blue".equals(this.name)) {
                return LocaleController.getString("ThemeDark", R.string.ThemeDark);
            }
            if ("Graphite".equals(this.name)) {
                return LocaleController.getString("ThemeGraphite", R.string.ThemeGraphite);
            }
            if ("Arctic Blue".equals(this.name)) {
                return LocaleController.getString("ThemeArcticBlue", R.string.ThemeArcticBlue);
            }
            TLRPC.TL_theme tL_theme = this.info;
            return tL_theme != null ? tL_theme.title : this.name;
        }

        public boolean isDark() {
            return "Dark Blue".equals(this.name) || "Graphite".equals(this.name);
        }

        public boolean isLight() {
            return this.pathToFile == null && !isDark();
        }

        public String getKey() {
            if (this.info != null) {
                return "remote" + this.info.id;
            }
            return this.name;
        }

        static ThemeInfo createWithJson(JSONObject object) {
            if (object == null) {
                return null;
            }
            try {
                ThemeInfo themeInfo = new ThemeInfo();
                themeInfo.name = object.getString("name");
                themeInfo.pathToFile = object.getString("path");
                if (object.has("account")) {
                    themeInfo.account = object.getInt("account");
                }
                if (object.has("info")) {
                    try {
                        SerializedData serializedData = new SerializedData(Utilities.hexToBytes(object.getString("info")));
                        themeInfo.info = (TLRPC.TL_theme) TLRPC.Theme.TLdeserialize(serializedData, serializedData.readInt32(true), true);
                    } catch (Throwable e) {
                        FileLog.e(e);
                    }
                }
                if (object.has("loaded")) {
                    themeInfo.loaded = object.getBoolean("loaded");
                }
                return themeInfo;
            } catch (Exception e2) {
                FileLog.e(e2);
                return null;
            }
        }

        static ThemeInfo createWithString(String string) {
            if (TextUtils.isEmpty(string)) {
                return null;
            }
            String[] args = string.split("\\|");
            if (args.length != 2) {
                return null;
            }
            ThemeInfo themeInfo = new ThemeInfo();
            themeInfo.name = args[0];
            themeInfo.pathToFile = args[1];
            return themeInfo;
        }

        void setAccentColorOptions(int[] options) {
            this.accentColorOptions = options;
            int i = options[0];
            this.accentBaseColor = i;
            Color.colorToHSV(i, this.accentBaseColorHsv);
            setAccentColor(this.accentBaseColor);
        }

        void setAccentColor(int color) {
            this.accentColor = color;
            Color.colorToHSV(color, this.accentColorHsv);
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void loadThemeDocument() {
            this.loaded = false;
            NotificationCenter.getInstance(this.account).addObserver(this, NotificationCenter.fileDidLoad);
            NotificationCenter.getInstance(this.account).addObserver(this, NotificationCenter.fileDidFailToLoad);
            FileLoader.getInstance(this.account).loadFile(this.info.document, this.info, 1, 1);
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void removeObservers() {
            NotificationCenter.getInstance(this.account).removeObserver(this, NotificationCenter.fileDidLoad);
            NotificationCenter.getInstance(this.account).removeObserver(this, NotificationCenter.fileDidFailToLoad);
        }

        @Override // im.uwrkaxlmjj.messenger.NotificationCenter.NotificationCenterDelegate
        public void didReceivedNotification(int id, int account, Object... args) {
            if (id == NotificationCenter.fileDidLoad || id == NotificationCenter.fileDidFailToLoad) {
                String location = (String) args[0];
                TLRPC.TL_theme tL_theme = this.info;
                if (tL_theme != null && tL_theme.document != null) {
                    String name = FileLoader.getAttachFileName(this.info.document);
                    if (location.equals(name)) {
                        removeObservers();
                        if (id == NotificationCenter.fileDidLoad) {
                            this.loaded = true;
                            this.previewParsed = false;
                            Theme.saveOtherThemes(true);
                            if (this == Theme.currentTheme && Theme.previousTheme == null) {
                                Theme.applyTheme(this, this == Theme.currentNightTheme);
                            }
                        }
                    }
                }
            }
        }
    }

    static {
        ThemeInfo t;
        selectedAutoNightType = 0;
        autoNightBrighnessThreshold = 0.25f;
        autoNightDayStartTime = 1320;
        autoNightDayEndTime = 480;
        autoNightSunsetTime = 1320;
        autoNightLastSunCheckDay = -1;
        autoNightSunriseTime = 480;
        autoNightCityName = "";
        autoNightLocationLatitude = 10000.0d;
        autoNightLocationLongitude = 10000.0d;
        HashMap<String, Integer> map = defaultColors;
        Integer numValueOf = Integer.valueOf(value_brandDefault);
        map.put(key_brandDefault, numValueOf);
        defaultColors.put(key_brandDark, Integer.valueOf(value_brandDark));
        defaultColors.put(key_brandDarkMode, Integer.valueOf(value_brandDarkMode));
        defaultColors.put(key_brandLight, Integer.valueOf(value_brandLight));
        defaultColors.put(key_brandBG, -2959879);
        HashMap<String, Integer> map2 = defaultColors;
        Integer numValueOf2 = Integer.valueOf(value_neutralActive);
        map2.put(key_neutralActive, numValueOf2);
        defaultColors.put(key_neutralDark, Integer.valueOf(value_neutralDark));
        defaultColors.put(key_neutralBody, Integer.valueOf(value_neutralBody));
        defaultColors.put(key_neutralWeak, Integer.valueOf(value_neutralWeak));
        defaultColors.put(key_neutralDisabled, Integer.valueOf(value_neutralDisabled));
        defaultColors.put(key_neutralLine, Integer.valueOf(value_neutralLine));
        defaultColors.put(key_neutralSecondaryBG, Integer.valueOf(value_neutralSecondaryBG));
        defaultColors.put(key_neutralWhite, -1);
        defaultColors.put(key_accentError, Integer.valueOf(value_accentError));
        defaultColors.put(key_accentWarning, Integer.valueOf(value_accentWarning));
        defaultColors.put(key_accentSuccess, Integer.valueOf(value_accentSuccess));
        defaultColors.put(key_accentOrange, Integer.valueOf(value_accentOrange));
        defaultColors.put(key_accentBlue, Integer.valueOf(value_accentBlue));
        defaultColors.put(key_accentSafe, Integer.valueOf(value_accentSafe));
        defaultColors.put(key_gradient1Location1, -2959879);
        defaultColors.put(key_gradient1Location2, Integer.valueOf(value_gradient1Location2));
        defaultColors.put(key_gradient2Location1, Integer.valueOf(value_gradient2Location1));
        defaultColors.put(key_gradient2Location2, Integer.valueOf(value_gradient2Location2));
        defaultColors.put(key_pageBackgroundColor, Integer.valueOf(value_pageBackgroundColor));
        defaultColors.put(key_WalletPageBlueTextColor, Integer.valueOf(value_WalletPageBlueTextColor));
        defaultColors.put(key_blackAlpha30, Integer.valueOf(value_blackAlpha30));
        defaultColors.put(key_blackAlpha70, Integer.valueOf(value_blackAlpha70));
        defaultColors.put(key_blackAlpha80, Integer.valueOf(value_blackAlpha80));
        defaultColors.put(key_shadowColor, Integer.valueOf(value_shadowColor));
        defaultColors.put(key_bottomBarBackground, -1);
        defaultColors.put(key_bottomBarNormalColor, Integer.valueOf(value_neutralDisabled));
        defaultColors.put(key_bottomBarSelectedColor, numValueOf);
        defaultColors.put(key_list_decorationTextColor, -8026747);
        defaultColors.put(key_list_decorationBackground, -328966);
        defaultColors.put(key_sidebar_textDefaultColor, -6118750);
        defaultColors.put(key_contacts_userCellDeleteBackground, -7612417);
        defaultColors.put(key_contacts_userCellDeleteText, -1);
        defaultColors.put(key_searchview_solidColor, -1);
        defaultColors.put(key_searchview_strokeColor, -1);
        defaultColors.put(key_dialogBackground, -1);
        defaultColors.put(key_dialogBackgroundGray, -986896);
        defaultColors.put(key_dialogTextBlack, -14540254);
        defaultColors.put(key_dialogTextLink, -14255946);
        defaultColors.put(key_dialogLinkSelection, 862104035);
        defaultColors.put(key_dialogTextRed, -3319206);
        defaultColors.put(key_dialogTextRed2, -2213318);
        defaultColors.put(key_dialogTextBlue, -13660983);
        defaultColors.put(key_dialogTextBlue2, -12937771);
        defaultColors.put(key_dialogTextBlue3, -12664327);
        defaultColors.put(key_dialogTextBlue4, -15095832);
        defaultColors.put(key_dialogTextGray, -13333567);
        defaultColors.put(key_dialogTextGray2, -9079435);
        defaultColors.put(key_dialogTextGray3, -6710887);
        defaultColors.put(key_dialogTextGray4, -5000269);
        defaultColors.put(key_dialogTextHint, -6842473);
        defaultColors.put(key_dialogIcon, -9999504);
        defaultColors.put(key_dialogRedIcon, -2011827);
        defaultColors.put(key_dialogGrayLine, -2960686);
        defaultColors.put(key_dialogTopBackground, -9456923);
        defaultColors.put(key_dialogInputField, -2368549);
        defaultColors.put(key_dialogInputFieldActivated, -13129232);
        defaultColors.put(key_dialogCheckboxSquareBackground, -12345121);
        defaultColors.put(key_dialogCheckboxSquareCheck, -1);
        defaultColors.put(key_dialogCheckboxSquareUnchecked, -9211021);
        defaultColors.put(key_dialogCheckboxSquareDisabled, -5197648);
        defaultColors.put(key_dialogRadioBackground, -5000269);
        defaultColors.put(key_dialogRadioBackgroundChecked, -13129232);
        defaultColors.put(key_dialogProgressCircle, -11371101);
        defaultColors.put(key_dialogLineProgress, -11371101);
        defaultColors.put(key_dialogLineProgressBackground, -2368549);
        defaultColors.put(key_dialogButton, -11955764);
        defaultColors.put(key_dialogButtonSelector, 251658240);
        defaultColors.put(key_dialogScrollGlow, -657673);
        defaultColors.put(key_dialogRoundCheckBox, -11750155);
        defaultColors.put(key_dialogRoundCheckBoxCheck, -1);
        defaultColors.put(key_dialogBadgeBackground, -45765);
        defaultColors.put(key_dialogBadgeText, -1);
        defaultColors.put(key_dialogCameraIcon, -1);
        defaultColors.put(key_dialog_inlineProgressBackground, -151981323);
        defaultColors.put(key_dialog_inlineProgress, -9735304);
        defaultColors.put(key_dialogSearchBackground, -854795);
        defaultColors.put(key_dialogSearchHint, -6774617);
        defaultColors.put(key_dialogSearchIcon, -6182737);
        defaultColors.put(key_dialogSearchText, -14540254);
        defaultColors.put(key_dialogFloatingButton, -11750155);
        defaultColors.put(key_dialogFloatingButtonPressed, -11750155);
        defaultColors.put(key_dialogFloatingIcon, -1);
        defaultColors.put(key_dialogShadowLine, 301989888);
        defaultColors.put(key_windowBackgroundValueText1, -5789785);
        defaultColors.put(key_windowBackgroundGrayText, -460552);
        defaultColors.put(key_windowBackgroundWhite, -1);
        defaultColors.put(key_windowBackgroundUnchecked, -6445135);
        defaultColors.put(key_windowBackgroundChecked, -11034919);
        defaultColors.put(key_windowBackgroundCheckText, -1);
        defaultColors.put(key_progressCircle, -11371101);
        defaultColors.put(key_windowBackgroundWhiteGrayIcon, -8288629);
        defaultColors.put(key_windowBackgroundWhiteBlueText, -16680193);
        defaultColors.put(key_windowBackgroundWhiteBlueText2, -12937771);
        defaultColors.put(key_windowBackgroundWhiteBlueText3, -14255946);
        defaultColors.put(key_windowBackgroundWhiteBlueText4, -11697229);
        defaultColors.put(key_windowBackgroundWhiteBlueText5, -11759926);
        defaultColors.put(key_windowBackgroundWhiteBlueText6, -12940081);
        defaultColors.put(key_windowBackgroundWhiteBlueText7, -13141330);
        defaultColors.put(key_windowBackgroundWhiteBlueButton, numValueOf);
        defaultColors.put(key_windowBackgroundWhiteBlueIcon, -16680193);
        defaultColors.put(key_windowBackgroundWhiteGreenText, -14248148);
        defaultColors.put(key_windowBackgroundWhiteGreenText2, -13129704);
        defaultColors.put(key_windowBackgroundWhiteRedText, -3319206);
        defaultColors.put(key_windowBackgroundWhiteRedText2, -2404015);
        defaultColors.put(key_windowBackgroundWhiteRedText3, -2995895);
        defaultColors.put(key_windowBackgroundWhiteRedText4, -3198928);
        defaultColors.put(key_windowBackgroundWhiteRedText5, -1230535);
        defaultColors.put(key_windowBackgroundWhiteRedText6, -39322);
        defaultColors.put(key_windowBackgroundWhiteGrayText, -8156010);
        defaultColors.put(key_windowBackgroundWhiteGrayText2, -7697782);
        defaultColors.put(key_windowBackgroundWhiteGrayText3, -6710887);
        defaultColors.put(key_windowBackgroundWhiteGrayText4, -8355712);
        defaultColors.put(key_windowBackgroundWhiteGrayText5, -6052957);
        defaultColors.put(key_windowBackgroundWhiteGrayText6, -9079435);
        defaultColors.put(key_windowBackgroundWhiteGrayText7, -3750202);
        defaultColors.put(key_windowBackgroundWhiteGrayText8, -9605774);
        defaultColors.put(key_windowBackgroundWhiteGrayLine, -2368549);
        defaultColors.put(key_windowBackgroundWhiteBlackText, numValueOf2);
        defaultColors.put(key_windowBackgroundWhiteHintText, -5723992);
        defaultColors.put(key_windowBackgroundWhiteValueText, -12937771);
        defaultColors.put(key_windowBackgroundWhiteLinkText, -14255946);
        defaultColors.put(key_windowBackgroundWhiteLinkSelection, 862104035);
        defaultColors.put(key_windowBackgroundWhiteBlueHeader, -12937771);
        defaultColors.put(key_windowBackgroundWhiteInputField, -2368549);
        defaultColors.put(key_windowBackgroundWhiteInputFieldActivated, -13129232);
        defaultColors.put(key_switchTrack, -6908264);
        defaultColors.put(key_switchTrackChecked, -14370989);
        defaultColors.put(key_switchTrackBlue, -8221031);
        defaultColors.put(key_switchTrackBlueChecked, -12810041);
        defaultColors.put(key_switchTrackBlueThumb, -1);
        defaultColors.put(key_switchTrackBlueThumbChecked, -1);
        defaultColors.put(key_switchTrackBlueSelector, 390089299);
        defaultColors.put(key_switchTrackBlueSelectorChecked, 553797505);
        defaultColors.put(key_switch2Track, -688514);
        defaultColors.put(key_switch2TrackChecked, -11358743);
        defaultColors.put(key_checkboxSquareBackground, -12345121);
        defaultColors.put(key_checkboxSquareCheck, -1);
        defaultColors.put(key_checkboxSquareUnchecked, -3881788);
        defaultColors.put(key_checkboxSquareDisabled, -5197648);
        defaultColors.put(key_listSelector, 251658240);
        defaultColors.put(key_radioBackground, -5000269);
        defaultColors.put(key_radioBackgroundChecked, -13129232);
        defaultColors.put(key_windowBackgroundGray, -526599);
        defaultColors.put(key_windowBackgroundGrayShadow, -16777216);
        defaultColors.put(key_emptyListPlaceholder, -6974059);
        defaultColors.put(key_divider, -2500135);
        defaultColors.put(key_graySection, -1117195);
        defaultColors.put(key_graySectionText, -3881788);
        defaultColors.put(key_contextProgressInner1, -4202506);
        defaultColors.put(key_contextProgressOuter1, -13920542);
        defaultColors.put(key_contextProgressInner2, -4202506);
        defaultColors.put(key_contextProgressOuter2, -1);
        defaultColors.put(key_contextProgressInner3, -5000269);
        defaultColors.put(key_contextProgressOuter3, -1);
        defaultColors.put(key_contextProgressInner4, -3486256);
        defaultColors.put(key_contextProgressOuter4, -13683656);
        defaultColors.put(key_fastScrollActive, -11361317);
        defaultColors.put(key_fastScrollInactive, -3551791);
        defaultColors.put(key_fastScrollText, -1);
        defaultColors.put(key_avatar_text, -1);
        defaultColors.put(key_avatar_backgroundSaved, -10043398);
        defaultColors.put(key_avatar_backgroundArchived, -5654847);
        defaultColors.put(key_avatar_backgroundArchivedHidden, -3749428);
        defaultColors.put(key_avatar_backgroundRed, -1743531);
        defaultColors.put(key_avatar_backgroundOrange, -881592);
        defaultColors.put(key_avatar_backgroundViolet, -7436818);
        defaultColors.put(key_avatar_backgroundGreen, -8992691);
        defaultColors.put(key_avatar_backgroundCyan, -10502443);
        defaultColors.put(key_avatar_backgroundBlue, -11232035);
        defaultColors.put(key_avatar_backgroundPink, -887654);
        defaultColors.put(key_avatar_backgroundGroupCreateSpanBlue, -1642505);
        defaultColors.put(key_avatar_backgroundInProfileBlue, -11500111);
        defaultColors.put(key_avatar_backgroundActionBarBlue, -10907718);
        defaultColors.put(key_avatar_subtitleInProfileBlue, -2626822);
        defaultColors.put(key_avatar_actionBarSelectorBlue, -11959891);
        defaultColors.put(key_avatar_actionBarIconBlue, -1);
        defaultColors.put(key_avatar_nameInMessageRed, -3516848);
        defaultColors.put(key_avatar_nameInMessageOrange, -2589911);
        defaultColors.put(key_avatar_nameInMessageViolet, -11627828);
        defaultColors.put(key_avatar_nameInMessageGreen, -11488718);
        defaultColors.put(key_avatar_nameInMessageCyan, -13132104);
        defaultColors.put(key_avatar_nameInMessageBlue, -11627828);
        defaultColors.put(key_avatar_nameInMessagePink, -11627828);
        defaultColors.put(key_actionBarDefault, -1);
        defaultColors.put(key_actionBarDefaultIcon, -16777216);
        defaultColors.put(key_actionBarActionModeDefault, -1);
        defaultColors.put(key_actionBarActionModeDefaultTop, Integer.valueOf(C.ENCODING_PCM_MU_LAW));
        defaultColors.put(key_actionBarActionModeDefaultIcon, -16777216);
        defaultColors.put(key_actionBarDefaultTitle, numValueOf2);
        defaultColors.put(key_actionBarDefaultSubtitle, -8156010);
        defaultColors.put(key_actionBarDefaultSelector, -12554860);
        defaultColors.put(key_actionBarWhiteSelector, Integer.valueOf(ACTION_BAR_AUDIO_SELECTOR_COLOR));
        defaultColors.put(key_actionBarDefaultSearch, -16777216);
        defaultColors.put(key_actionBarDefaultSearchPlaceholder, Integer.valueOf(BannerConfig.INDICATOR_SELECTED_COLOR));
        defaultColors.put(key_actionBarDefaultSubmenuItem, numValueOf2);
        defaultColors.put(key_actionBarDefaultSubmenuItemIcon, -6775116);
        defaultColors.put(key_actionBarDefaultSubmenuBackground, -1);
        defaultColors.put(key_actionBarActionModeDefaultSelector, -986896);
        defaultColors.put(key_actionBarTabActiveText, -16680193);
        defaultColors.put(key_actionBarTabUnactiveText, -3217921);
        defaultColors.put(key_actionBarTabLine, -16680193);
        defaultColors.put(key_actionBarTabSelector, -2758409);
        defaultColors.put(key_actionBarBrowser, -1);
        defaultColors.put(key_actionBarDefaultArchived, -9471353);
        defaultColors.put(key_actionBarDefaultArchivedSelector, -10590350);
        defaultColors.put(key_actionBarDefaultArchivedIcon, -1);
        defaultColors.put(key_actionBarDefaultArchivedTitle, -1);
        defaultColors.put(key_actionBarDefaultArchivedSearch, -1);
        defaultColors.put(key_actionBarDefaultArchivedSearchPlaceholder, Integer.valueOf(BannerConfig.INDICATOR_NORMAL_COLOR));
        defaultColors.put(key_chats_onlineCircle, -11810020);
        defaultColors.put(key_chats_unreadCounter, -45765);
        defaultColors.put(key_chats_unreadCounterMuted, -3749428);
        defaultColors.put(key_chats_unreadCounterText, -1);
        defaultColors.put(key_chats_archiveBackground, -10049056);
        defaultColors.put(key_chats_archivePinBackground, -6313293);
        defaultColors.put(key_chats_archiveIcon, -1);
        defaultColors.put(key_chats_archiveText, -1);
        defaultColors.put(key_chats_name, numValueOf2);
        defaultColors.put(key_chats_nameArchived, -11382190);
        defaultColors.put(key_chats_secretName, -16734706);
        defaultColors.put(key_chats_secretIcon, -15093466);
        defaultColors.put(key_chats_nameIcon, -14408668);
        defaultColors.put(key_chats_pinnedIcon, -1312257);
        defaultColors.put(key_chats_message, -7631473);
        defaultColors.put(key_chats_messageArchived, -7237231);
        defaultColors.put(key_chats_message_threeLines, -7434095);
        defaultColors.put(key_chats_draft, -2274503);
        defaultColors.put(key_chats_nameMessage, -7289089);
        defaultColors.put(key_chats_nameMessageArchived, -7631473);
        defaultColors.put(key_chats_nameMessage_threeLines, -7289089);
        defaultColors.put(key_chats_nameMessageArchived_threeLines, -10592674);
        defaultColors.put(key_chats_attachMessage, -12812624);
        defaultColors.put(key_chats_actionMessage, -12812624);
        defaultColors.put(key_chats_date, -6973028);
        defaultColors.put(key_chats_pinnedOverlay, 134217728);
        defaultColors.put(key_chats_tabletSelectedOverlay, 251658240);
        defaultColors.put(key_chats_sentCheck, -12146122);
        defaultColors.put(key_chats_sentReadCheck, -12146122);
        defaultColors.put(key_chats_sentClock, -12402945);
        defaultColors.put(key_chats_sentError, -570319);
        defaultColors.put(key_chats_sentErrorIcon, -1);
        defaultColors.put(key_chats_verifiedBackground, -13391642);
        defaultColors.put(key_chats_verifiedCheck, -1);
        defaultColors.put(key_chats_muteIcon, -4341308);
        defaultColors.put(key_chats_mentionIcon, -1);
        defaultColors.put(key_chats_menuBackground, -1);
        defaultColors.put(key_chats_menuItemText, -12303292);
        defaultColors.put(key_chats_menuItemCheck, -10907718);
        defaultColors.put(key_chats_menuItemIcon, -7827048);
        defaultColors.put(key_chats_menuName, -1);
        defaultColors.put(key_chats_menuPhone, -1);
        defaultColors.put(key_chats_menuPhoneCats, -4004353);
        defaultColors.put(key_chats_menuCloud, -1);
        defaultColors.put(key_chats_menuCloudBackgroundCats, -12420183);
        defaultColors.put(key_chats_actionIcon, -1);
        defaultColors.put(key_chats_actionBackground, -10114592);
        defaultColors.put(key_chats_actionPressedBackground, -11100714);
        defaultColors.put(key_chats_actionUnreadIcon, -9211021);
        defaultColors.put(key_chats_actionUnreadBackground, -1);
        defaultColors.put(key_chats_actionUnreadPressedBackground, -855310);
        defaultColors.put(key_chats_menuTopBackgroundCats, -10907718);
        defaultColors.put(key_chat_attachMediaBanBackground, -12171706);
        defaultColors.put(key_chat_attachMediaBanText, -1);
        defaultColors.put(key_chat_attachCheckBoxCheck, -1);
        defaultColors.put(key_chat_attachCheckBoxBackground, -12995849);
        defaultColors.put(key_chat_attachPhotoBackground, 134217728);
        defaultColors.put(key_chat_attachActiveTab, -13391883);
        defaultColors.put(key_chat_attachUnactiveTab, -7169634);
        defaultColors.put(key_chat_attachPermissionImage, numValueOf2);
        defaultColors.put(key_chat_attachPermissionMark, -1945520);
        defaultColors.put(key_chat_attachPermissionText, -9472134);
        defaultColors.put(key_chat_attachEmptyImage, -3355444);
        defaultColors.put(key_chat_attachGalleryBackground, -12214795);
        defaultColors.put(key_chat_attachGalleryIcon, -1);
        defaultColors.put(key_chat_attachAudioBackground, -1351584);
        defaultColors.put(key_chat_attachAudioIcon, -1);
        defaultColors.put(key_chat_attachFileBackground, -13321743);
        defaultColors.put(key_chat_attachFileIcon, -1);
        defaultColors.put(key_chat_attachContactBackground, -868277);
        defaultColors.put(key_chat_attachContactIcon, -1);
        defaultColors.put(key_chat_attachLocationBackground, -13187226);
        defaultColors.put(key_chat_attachLocationIcon, -1);
        defaultColors.put(key_chat_attachPollBackground, -868277);
        defaultColors.put(key_chat_attachPollIcon, -1);
        defaultColors.put(key_chat_status, -2758409);
        defaultColors.put(key_chat_inGreenCall, -16725933);
        defaultColors.put(key_chat_inRedCall, -47032);
        defaultColors.put(key_chat_outGreenCall, -16725933);
        defaultColors.put(key_chat_shareBackground, 1718783910);
        defaultColors.put(key_chat_shareBackgroundSelected, -1720545370);
        defaultColors.put(key_chat_lockIcon, -1);
        defaultColors.put(key_chat_muteIcon, -5124893);
        defaultColors.put(key_chat_inBubble, -1);
        defaultColors.put(key_chat_inBubbleSelected, -1);
        defaultColors.put(key_chat_inBubbleShadow, 255013683);
        defaultColors.put(key_chat_outBubble, numValueOf);
        defaultColors.put(key_chat_outBubbleSelected, numValueOf);
        defaultColors.put(key_chat_outBubbleShadow, numValueOf);
        defaultColors.put(key_chat_outMediaBubbleShadow, 255013683);
        defaultColors.put(key_chat_inMediaIcon, 872415231);
        defaultColors.put(key_chat_inMediaIconSelected, 872415231);
        defaultColors.put(key_chat_outMediaIcon, 872415231);
        defaultColors.put(key_chat_outMediaIconSelected, 872415231);
        defaultColors.put(key_chat_messageTextIn, numValueOf2);
        defaultColors.put(key_chat_messageTextOut, -1);
        defaultColors.put(key_chat_messageLinkIn, -11048043);
        defaultColors.put(key_chat_messageLinkOut, -11048043);
        defaultColors.put(key_chat_serviceText, -1);
        defaultColors.put(key_chat_serviceLink, -1);
        defaultColors.put(key_chat_serviceIcon, -1);
        defaultColors.put(key_chat_mediaTimeBackground, 1711276032);
        defaultColors.put(key_chat_outSentCheck, -1);
        defaultColors.put(key_chat_outSentCheckSelected, -1);
        defaultColors.put(key_chat_outSentCheckRead, -1);
        defaultColors.put(key_chat_outSentCheckReadSelected, -1);
        defaultColors.put(key_chat_mediaSentCheck, -1);
        defaultColors.put(key_chat_outSentClock, -1);
        defaultColors.put(key_chat_outSentClockSelected, -1);
        defaultColors.put(key_chat_inSentClock, -6182221);
        defaultColors.put(key_chat_inSentClockSelected, -7094838);
        defaultColors.put(key_chat_mediaSentClock, -1);
        defaultColors.put(key_chat_inViews, -6182221);
        defaultColors.put(key_chat_inViewsSelected, -7094838);
        defaultColors.put(key_chat_outViews, -9522601);
        defaultColors.put(key_chat_outViewsSelected, -9522601);
        defaultColors.put(key_chat_mediaViews, -1);
        defaultColors.put(key_chat_inMenu, -4801083);
        defaultColors.put(key_chat_inMenuSelected, -6766130);
        defaultColors.put(key_chat_outMenu, -7221634);
        defaultColors.put(key_chat_outMenuSelected, -7221634);
        defaultColors.put(key_chat_mediaMenu, -1);
        defaultColors.put(key_chat_outInstant, -1);
        defaultColors.put(key_chat_outInstantSelected, -12019389);
        defaultColors.put(key_chat_inInstant, -12940081);
        defaultColors.put(key_chat_inInstantSelected, -13600331);
        defaultColors.put(key_chat_sentError, -2411211);
        defaultColors.put(key_chat_sentErrorIcon, -1);
        defaultColors.put(key_chat_selectedBackground, 671781104);
        defaultColors.put(key_chat_previewDurationText, -1);
        defaultColors.put(key_chat_previewGameText, -1);
        defaultColors.put(key_chat_inPreviewInstantText, -12940081);
        defaultColors.put(key_chat_outPreviewInstantText, -1);
        defaultColors.put(key_chat_inPreviewInstantSelectedText, -13600331);
        defaultColors.put(key_chat_outPreviewInstantSelectedText, -12019389);
        defaultColors.put(key_chat_secretTimeText, -1776928);
        defaultColors.put(key_chat_stickerNameText, -1);
        defaultColors.put(key_chat_botButtonText, -1);
        defaultColors.put(key_chat_botProgress, -1);
        defaultColors.put(key_chat_inForwardedNameText, -13072697);
        defaultColors.put(key_chat_outForwardedNameText, -1);
        defaultColors.put(key_chat_inViaBotNameText, -12940081);
        defaultColors.put(key_chat_outViaBotNameText, -1);
        defaultColors.put(key_chat_stickerViaBotNameText, -1);
        defaultColors.put(key_chat_inReplyLine, -12216004);
        defaultColors.put(key_chat_outReplyLine, -1);
        defaultColors.put(key_chat_stickerReplyLine, -1);
        defaultColors.put(key_chat_inReplyNameText, -12216004);
        defaultColors.put(key_chat_outReplyNameText, -1);
        defaultColors.put(key_chat_stickerReplyNameText, -1);
        defaultColors.put(key_chat_inReplyMessageText, -16777216);
        defaultColors.put(key_chat_outReplyMessageText, -1);
        defaultColors.put(key_chat_inReplyMediaMessageText, -16777216);
        defaultColors.put(key_chat_outReplyMediaMessageText, -1);
        defaultColors.put(key_chat_inReplyMediaMessageSelectedText, -16777216);
        defaultColors.put(key_chat_outReplyMediaMessageSelectedText, -16777216);
        defaultColors.put(key_chat_stickerReplyMessageText, -1);
        defaultColors.put(key_chat_replyBackground, 583386565);
        defaultColors.put(key_chat_inPreviewLine, -9390872);
        defaultColors.put(key_chat_outPreviewLine, -1);
        defaultColors.put(key_chat_inSiteNameText, -12940081);
        defaultColors.put(key_chat_outSiteNameText, -1);
        defaultColors.put(key_chat_inContactNameText, -11625772);
        defaultColors.put(key_chat_outContactNameText, -1);
        defaultColors.put(key_chat_inContactPhoneText, -13683656);
        defaultColors.put(key_chat_inContactPhoneSelectedText, -13683656);
        defaultColors.put(key_chat_outContactPhoneText, -13286860);
        defaultColors.put(key_chat_outContactPhoneSelectedText, -13286860);
        defaultColors.put(key_chat_mediaProgress, -1);
        defaultColors.put(key_chat_inAudioProgress, -1);
        defaultColors.put(key_chat_outAudioProgress, -1048610);
        defaultColors.put(key_chat_inAudioSelectedProgress, -1050370);
        defaultColors.put(key_chat_outAudioSelectedProgress, -1967921);
        defaultColors.put(key_chat_mediaTimeText, -1);
        defaultColors.put(key_chat_inTimeText, -6182221);
        defaultColors.put(key_chat_outTimeText, -1);
        defaultColors.put(key_chat_adminText, -4143413);
        defaultColors.put(key_chat_adminSelectedText, -7752511);
        defaultColors.put(key_chat_inTimeSelectedText, -7752511);
        defaultColors.put(key_chat_outTimeSelectedText, -1);
        defaultColors.put(key_chat_inAudioPerformerText, -13683656);
        defaultColors.put(key_chat_inAudioPerformerSelectedText, -13683656);
        defaultColors.put(key_chat_outAudioPerformerText, -13286860);
        defaultColors.put(key_chat_outAudioPerformerSelectedText, -13286860);
        defaultColors.put(key_chat_inAudioTitleText, -11625772);
        defaultColors.put(key_chat_outAudioTitleText, -1);
        defaultColors.put(key_chat_inAudioDurationText, -11048043);
        defaultColors.put(key_chat_inAudioDurationSelectedText, -11048043);
        defaultColors.put(key_chat_outAudioDurationText, -1);
        defaultColors.put(key_chat_outAudioDurationSelectedText, -1);
        defaultColors.put(key_chat_inAudioSeekbar, -1774864);
        defaultColors.put(key_chat_inAudioCacheSeekbar, 1071966960);
        defaultColors.put(key_chat_outAudioSeekbar, -4463700);
        defaultColors.put(key_chat_outAudioCacheSeekbar, 1069278124);
        defaultColors.put(key_chat_inAudioSeekbarSelected, -4399384);
        defaultColors.put(key_chat_outAudioSeekbarSelected, -5644906);
        defaultColors.put(key_chat_inAudioSeekbarFill, -9259544);
        defaultColors.put(key_chat_outAudioSeekbarFill, -8863118);
        defaultColors.put(key_chat_outVoiceIcon, -1);
        defaultColors.put(key_chat_outVoiceSeekbar, -1);
        defaultColors.put(key_chat_outVoiceSeekbarSelected, -1);
        defaultColors.put(key_chat_outVoiceSeekbarFill, -1);
        defaultColors.put(key_chat_inVoiceIcon, -11048043);
        defaultColors.put(key_chat_inVoiceSeekbar, -11048043);
        defaultColors.put(key_chat_inVoiceSeekbarSelected, -14388324);
        defaultColors.put(key_chat_inVoiceSeekbarFill, -11837559);
        defaultColors.put(key_chat_inFileProgress, -1314571);
        defaultColors.put(key_chat_outFileProgress, -2427453);
        defaultColors.put(key_chat_inFileProgressSelected, -3413258);
        defaultColors.put(key_chat_outFileProgressSelected, -3806041);
        defaultColors.put(key_chat_inFileNameText, -16777216);
        defaultColors.put(key_chat_outFileNameText, -1);
        defaultColors.put(key_chat_inFileInfoText, -6182221);
        defaultColors.put(key_chat_outFileInfoText, -4934476);
        defaultColors.put(key_chat_inFileInfoSelectedText, -7752511);
        defaultColors.put(key_chat_outFileInfoSelectedText, -6182221);
        defaultColors.put(key_chat_inFileBackground, -1314571);
        defaultColors.put(key_chat_outFileBackground, -2427453);
        defaultColors.put(key_chat_inFileBackgroundSelected, -3413258);
        defaultColors.put(key_chat_outFileBackgroundSelected, -3806041);
        defaultColors.put(key_chat_inVenueInfoText, -6182221);
        defaultColors.put(key_chat_outVenueInfoText, -10112933);
        defaultColors.put(key_chat_inVenueInfoSelectedText, -7752511);
        defaultColors.put(key_chat_outVenueInfoSelectedText, -10112933);
        defaultColors.put(key_chat_mediaInfoText, -1);
        defaultColors.put(key_chat_linkSelectBackground, 862104035);
        defaultColors.put(key_chat_textSelectBackground, 1717742051);
        defaultColors.put(key_chat_emojiPanelBackground, -986379);
        defaultColors.put(key_chat_emojiPanelBadgeBackground, -11688214);
        defaultColors.put(key_chat_emojiPanelBadgeText, -1);
        defaultColors.put(key_chat_emojiSearchBackground, -1709586);
        defaultColors.put(key_chat_emojiSearchIcon, -7036497);
        defaultColors.put(key_chat_emojiPanelShadowLine, 301989888);
        defaultColors.put(key_chat_emojiPanelEmptyText, -7038047);
        defaultColors.put(key_chat_emojiPanelIcon, -6445909);
        defaultColors.put(key_chat_emojiBottomPanelIcon, -7564905);
        defaultColors.put(key_chat_emojiPanelIconSelected, -13920286);
        defaultColors.put(key_chat_emojiPanelStickerPackSelector, -1907225);
        defaultColors.put(key_chat_emojiPanelStickerPackSelectorLine, -11097104);
        defaultColors.put(key_chat_emojiPanelBackspace, -7564905);
        defaultColors.put(key_chat_emojiPanelMasksIcon, -1);
        defaultColors.put(key_chat_emojiPanelMasksIconSelected, -10305560);
        defaultColors.put(key_chat_emojiPanelTrendingTitle, -14540254);
        defaultColors.put(key_chat_emojiPanelStickerSetName, -8221804);
        defaultColors.put(key_chat_emojiPanelStickerSetNameHighlight, -14184997);
        defaultColors.put(key_chat_emojiPanelStickerSetNameIcon, -5130564);
        defaultColors.put(key_chat_emojiPanelTrendingDescription, -7697782);
        defaultColors.put(key_chat_botKeyboardButtonText, -13220017);
        defaultColors.put(key_chat_botKeyboardButtonBackground, -1775639);
        defaultColors.put(key_chat_botKeyboardButtonBackgroundPressed, -3354156);
        defaultColors.put(key_chat_unreadMessagesStartArrowIcon, -6113849);
        defaultColors.put(key_chat_unreadMessagesStartText, -6710887);
        defaultColors.put(key_chat_unreadMessagesStartBackground, -1);
        defaultColors.put(key_chat_inFileIcon, -6113849);
        defaultColors.put(key_chat_inFileSelectedIcon, -7883067);
        defaultColors.put(key_chat_outFileIcon, -8011912);
        defaultColors.put(key_chat_outFileSelectedIcon, -8011912);
        defaultColors.put(key_chat_inLocationBackground, -1314571);
        defaultColors.put(key_chat_inLocationIcon, -6113849);
        defaultColors.put(key_chat_outLocationBackground, -2427453);
        defaultColors.put(key_chat_outLocationIcon, -7880840);
        defaultColors.put(key_chat_inContactBackground, -9259544);
        defaultColors.put(key_chat_inContactIcon, -1);
        defaultColors.put(key_chat_outContactBackground, -8863118);
        defaultColors.put(key_chat_outContactIcon, -1048610);
        defaultColors.put(key_chat_outBroadcast, -12146122);
        defaultColors.put(key_chat_mediaBroadcast, -1);
        defaultColors.put(key_chat_searchPanelIcons, -9999761);
        defaultColors.put(key_chat_searchPanelText, -9999761);
        defaultColors.put(key_chat_secretChatStatusText, -8421505);
        defaultColors.put(key_chat_fieldOverlayText, -12940081);
        defaultColors.put(key_chat_stickersHintPanel, -1);
        defaultColors.put(key_chat_replyPanelIcons, -11032346);
        defaultColors.put(key_chat_replyPanelClose, -7432805);
        defaultColors.put(key_chat_replyPanelName, -12940081);
        defaultColors.put(key_chat_replyPanelMessage, -14540254);
        defaultColors.put(key_chat_replyPanelLine, -1513240);
        defaultColors.put(key_chat_messagePanelBackground, -986379);
        defaultColors.put(key_chat_messagePanelText, -16777216);
        defaultColors.put(key_chat_messagePanelMetionText, -11048043);
        defaultColors.put(key_chat_messagePanelHint, -5985101);
        defaultColors.put(key_chat_messagePanelCursor, -11230757);
        defaultColors.put(key_chat_messagePanelShadow, -16777216);
        defaultColors.put(key_chat_messagePanelIcons, -7432805);
        defaultColors.put(key_chat_messagePanelVideoFrame, -11817481);
        defaultColors.put(key_chat_recordedVoicePlayPause, -1);
        defaultColors.put(key_chat_recordedVoicePlayPausePressed, -2495749);
        defaultColors.put(key_chat_recordedVoiceDot, -2468275);
        defaultColors.put(key_chat_recordedVoiceBackground, -11165981);
        defaultColors.put(key_chat_recordedVoiceProgress, -6107400);
        defaultColors.put(key_chat_recordedVoiceProgressInner, -1);
        defaultColors.put(key_chat_recordVoiceCancel, -6710887);
        defaultColors.put(key_chat_messagePanelSend, -10309397);
        defaultColors.put(key_chat_messagePanelSendPressed, -1);
        defaultColors.put(key_chat_messagePanelVoiceLock, Integer.valueOf(value_neutralWeak));
        defaultColors.put(key_chat_messagePanelVoiceLockBackground, -1);
        defaultColors.put(key_chat_messagePanelVoiceLockShadow, -16777216);
        defaultColors.put(key_chat_recordTime, -11711413);
        defaultColors.put(key_chat_emojiPanelNewTrending, -11688214);
        defaultColors.put(key_chat_gifSaveHintText, -1);
        defaultColors.put(key_chat_gifSaveHintBackground, -871296751);
        defaultColors.put(key_chat_goDownButton, -1);
        defaultColors.put(key_chat_goDownButtonShadow, -16777216);
        defaultColors.put(key_chat_goDownButtonIcon, -7432805);
        defaultColors.put(key_chat_goDownButtonCounter, -1);
        defaultColors.put(key_chat_goDownButtonCounterBackground, -11689240);
        defaultColors.put(key_chat_messagePanelCancelInlineBot, -5395027);
        defaultColors.put(key_chat_messagePanelVoicePressed, -1);
        defaultColors.put(key_chat_messagePanelVoiceBackground, -11037236);
        defaultColors.put(key_chat_messagePanelVoiceShadow, 218103808);
        defaultColors.put(key_chat_messagePanelVoiceDelete, -9211021);
        defaultColors.put(key_chat_messagePanelVoiceDuration, -1);
        defaultColors.put(key_chat_inlineResultIcon, -11037236);
        defaultColors.put(key_chat_topPanelBackground, -1);
        defaultColors.put(key_chat_topPanelClose, -7563878);
        defaultColors.put(key_chat_topPanelLine, -9658414);
        defaultColors.put(key_chat_topPanelTitle, -12940081);
        defaultColors.put(key_chat_topPanelMessage, -6710887);
        defaultColors.put(key_chat_reportSpam, -3188393);
        defaultColors.put(key_chat_addContact, -11894091);
        defaultColors.put(key_chat_inLoader, -11048043);
        defaultColors.put(key_chat_inLoaderSelected, -11048043);
        defaultColors.put(key_live_mute, -105179);
        defaultColors.put(key_live_unmute, -1973274);
        defaultColors.put(key_chat_outLoader, numValueOf);
        defaultColors.put(key_chat_outLoaderSelected, -1);
        defaultColors.put(key_chat_outDocumentLoader, -2171170);
        defaultColors.put(key_chat_outDocumentLoaderSelected, -2171170);
        defaultColors.put(key_chats_sersviceBackground, -1713644581);
        defaultColors.put(key_chat_redpacketServiceText, -6710887);
        defaultColors.put(key_chat_redpacketLinkServiceText, -10066330);
        defaultColors.put(key_chat_inLoaderPhoto, -6113080);
        defaultColors.put(key_chat_inLoaderPhotoSelected, -6113849);
        defaultColors.put(key_chat_inLoaderPhotoIcon, -197380);
        defaultColors.put(key_chat_inLoaderPhotoIconSelected, -1314571);
        defaultColors.put(key_chat_outLoaderPhoto, -8011912);
        defaultColors.put(key_chat_outLoaderPhotoSelected, -8538000);
        defaultColors.put(key_chat_outLoaderPhotoIcon, -2427453);
        defaultColors.put(key_chat_outLoaderPhotoIconSelected, -4134748);
        defaultColors.put(key_chat_mediaLoaderPhoto, 1711276032);
        defaultColors.put(key_chat_mediaLoaderPhotoSelected, Integer.valueOf(ACTION_BAR_PHOTO_VIEWER_COLOR));
        defaultColors.put(key_chat_mediaLoaderPhotoIcon, -1);
        defaultColors.put(key_chat_mediaLoaderPhotoIconSelected, -2500135);
        defaultColors.put(key_chat_secretTimerBackground, -868326258);
        defaultColors.put(key_chat_secretTimerText, -1);
        defaultColors.put(key_profile_creatorIcon, -12937771);
        defaultColors.put(key_profile_actionIcon, -8288630);
        defaultColors.put(key_profile_actionBackground, -1);
        defaultColors.put(key_profile_actionPressedBackground, -855310);
        defaultColors.put(key_profile_verifiedBackground, -5056776);
        defaultColors.put(key_profile_verifiedCheck, -11959368);
        defaultColors.put(key_profile_title, -1);
        defaultColors.put(key_profile_status, -2626822);
        defaultColors.put(key_player_actionBar, -1);
        defaultColors.put(key_player_actionBarSelector, 251658240);
        defaultColors.put(key_player_actionBarTitle, -13683656);
        defaultColors.put(key_player_actionBarTop, Integer.valueOf(SystemBarTintManager.DEFAULT_TINT_COLOR));
        defaultColors.put(key_player_actionBarSubtitle, -7697782);
        defaultColors.put(key_player_actionBarItems, -7697782);
        defaultColors.put(key_player_background, -1);
        defaultColors.put(key_player_time, -7564650);
        defaultColors.put(key_player_progressBackground, -1445899);
        defaultColors.put(key_player_progressCachedBackground, -1445899);
        defaultColors.put(key_player_progress, -11821085);
        defaultColors.put(key_player_placeholder, -5723992);
        defaultColors.put(key_player_placeholderBackground, -986896);
        defaultColors.put(key_player_button, numValueOf2);
        defaultColors.put(key_player_buttonActive, -11753238);
        defaultColors.put(key_sheet_scrollUp, -1973016);
        defaultColors.put(key_sheet_other, -3551789);
        defaultColors.put(key_files_folderIcon, -6710887);
        defaultColors.put(key_files_folderIconBackground, -986896);
        defaultColors.put(key_files_iconText, -1);
        defaultColors.put(key_sessions_devicesImage, -6908266);
        defaultColors.put(key_passport_authorizeBackground, -12211217);
        defaultColors.put(key_passport_authorizeBackgroundSelected, -12542501);
        defaultColors.put(key_passport_authorizeText, -1);
        defaultColors.put(key_location_sendLocationBackground, -9592620);
        defaultColors.put(key_location_sendLiveLocationBackground, -39836);
        defaultColors.put(key_location_sendLocationIcon, -1);
        defaultColors.put(key_location_sendLiveLocationIcon, -1);
        defaultColors.put(key_location_liveLocationProgress, -13262875);
        defaultColors.put(key_location_placeLocationBackground, -11753238);
        defaultColors.put(key_dialog_liveLocationProgress, -13262875);
        defaultColors.put(key_calls_callReceivedGreenIcon, -16725933);
        defaultColors.put(key_calls_callReceivedRedIcon, -47032);
        defaultColors.put(key_featuredStickers_addedIcon, -11491093);
        defaultColors.put(key_featuredStickers_buttonProgress, -11491093);
        defaultColors.put(key_featuredStickers_addButton, -11491093);
        defaultColors.put(key_featuredStickers_addButtonPressed, -12346402);
        defaultColors.put(key_featuredStickers_delButton, -2533545);
        defaultColors.put(key_featuredStickers_delButtonPressed, -3782327);
        defaultColors.put(key_featuredStickers_buttonText, -1);
        defaultColors.put(key_featuredStickers_unread, -11688214);
        defaultColors.put(key_inappPlayerPerformer, -13683656);
        defaultColors.put(key_inappPlayerTitle, -13683656);
        defaultColors.put(key_inappPlayerBackground, -1);
        defaultColors.put(key_inappPlayerPlayPause, -10309397);
        defaultColors.put(key_inappPlayerClose, -5723992);
        defaultColors.put(key_returnToCallBackground, -12279325);
        defaultColors.put(key_returnToCallText, -1);
        defaultColors.put(key_sharedMedia_startStopLoadIcon, -13196562);
        defaultColors.put(key_sharedMedia_linkPlaceholder, -986123);
        defaultColors.put(key_sharedMedia_linkPlaceholderText, -4735293);
        defaultColors.put(key_sharedMedia_photoPlaceholder, -1182729);
        defaultColors.put(key_sharedMedia_actionMode, -12154957);
        defaultColors.put(key_checkbox, -12862209);
        defaultColors.put(key_checkboxCheck, -1);
        defaultColors.put(key_checkboxDisabled, -5195326);
        defaultColors.put(key_stickers_menu, -4801083);
        defaultColors.put(key_stickers_menuSelector, 251658240);
        defaultColors.put(key_changephoneinfo_image, -4669499);
        defaultColors.put(key_changephoneinfo_image2, -11491350);
        defaultColors.put(key_groupcreate_hintText, -6182221);
        defaultColors.put(key_groupcreate_cursor, -11361317);
        defaultColors.put(key_groupcreate_sectionShadow, -16777216);
        defaultColors.put(key_groupcreate_sectionText, -8617336);
        defaultColors.put(key_groupcreate_spanText, -14540254);
        defaultColors.put(key_groupcreate_spanBackground, -855310);
        defaultColors.put(key_groupcreate_spanDelete, -1);
        defaultColors.put(key_contacts_inviteBackground, -11157919);
        defaultColors.put(key_contacts_inviteText, -1);
        defaultColors.put(key_login_progressInner, -1971470);
        defaultColors.put(key_login_progressOuter, -10313520);
        defaultColors.put(key_musicPicker_checkbox, -14043401);
        defaultColors.put(key_musicPicker_checkboxCheck, -1);
        defaultColors.put(key_musicPicker_buttonBackground, -10702870);
        defaultColors.put(key_musicPicker_buttonIcon, -1);
        defaultColors.put(key_picker_enabledButton, -15095832);
        defaultColors.put(key_picker_disabledButton, -6710887);
        defaultColors.put(key_picker_badge, -14043401);
        defaultColors.put(key_picker_badgeText, -1);
        defaultColors.put(key_chat_botSwitchToInlineText, -12348980);
        defaultColors.put(key_undo_background, -366530760);
        defaultColors.put(key_undo_cancelColor, -8008961);
        defaultColors.put(key_undo_infoColor, -1);
        defaultColors.put(key_walletDefaultBackground, -13714689);
        defaultColors.put(key_walletHoloBlueLight, -13388315);
        defaultColors.put(key_profileBottomBackgroundGray, -657931);
        defaultColors.put(key_profileBtnBackgroundGray, -1315861);
        defaultColors.put(key_profileBtnBackgroundBlue, -16733953);
        defaultColors.put(key_themeCheckBoxUnchecked, -986896);
        defaultColors.put(key_themeCheckBoxChecked, -14776109);
        defaultColors.put(key_themeCheckBoxDisabled, Integer.valueOf(value_pageBackgroundColor));
        defaultColors.put(key_color_42B71E, -12404962);
        fallbackKeys.put(key_chat_adminText, key_chat_inTimeText);
        fallbackKeys.put(key_chat_adminSelectedText, key_chat_inTimeSelectedText);
        fallbackKeys.put(key_player_progressCachedBackground, key_player_progressBackground);
        fallbackKeys.put(key_chat_inAudioCacheSeekbar, key_chat_inAudioSeekbar);
        fallbackKeys.put(key_chat_outAudioCacheSeekbar, key_chat_outAudioSeekbar);
        fallbackKeys.put(key_chat_emojiSearchBackground, key_chat_emojiPanelStickerPackSelector);
        fallbackKeys.put(key_location_sendLiveLocationIcon, key_location_sendLocationIcon);
        fallbackKeys.put(key_changephoneinfo_image2, key_featuredStickers_addButton);
        fallbackKeys.put(key_graySectionText, key_windowBackgroundWhiteGrayText2);
        fallbackKeys.put(key_chat_inMediaIcon, key_chat_inBubble);
        fallbackKeys.put(key_chat_outMediaIcon, key_chat_outBubble);
        fallbackKeys.put(key_chat_inMediaIconSelected, key_chat_inBubbleSelected);
        fallbackKeys.put(key_chat_outMediaIconSelected, key_chat_outBubbleSelected);
        fallbackKeys.put(key_chats_actionUnreadIcon, key_profile_actionIcon);
        fallbackKeys.put(key_chats_actionUnreadBackground, key_profile_actionBackground);
        fallbackKeys.put(key_chats_actionUnreadPressedBackground, key_profile_actionPressedBackground);
        fallbackKeys.put(key_dialog_inlineProgressBackground, key_windowBackgroundGray);
        fallbackKeys.put(key_dialog_inlineProgress, key_chats_menuItemIcon);
        fallbackKeys.put(key_groupcreate_spanDelete, key_chats_actionIcon);
        fallbackKeys.put(key_sharedMedia_photoPlaceholder, key_windowBackgroundGray);
        fallbackKeys.put(key_chat_attachPollBackground, key_chat_attachAudioBackground);
        fallbackKeys.put(key_chat_attachPollIcon, key_chat_attachAudioIcon);
        fallbackKeys.put(key_chats_onlineCircle, key_windowBackgroundWhiteBlueText);
        fallbackKeys.put(key_windowBackgroundWhiteBlueButton, key_windowBackgroundWhiteValueText);
        fallbackKeys.put(key_windowBackgroundWhiteBlueIcon, key_windowBackgroundWhiteValueText);
        fallbackKeys.put(key_undo_background, key_chat_gifSaveHintBackground);
        fallbackKeys.put(key_undo_cancelColor, key_chat_gifSaveHintText);
        fallbackKeys.put(key_undo_infoColor, key_chat_gifSaveHintText);
        fallbackKeys.put(key_windowBackgroundUnchecked, key_windowBackgroundWhite);
        fallbackKeys.put(key_windowBackgroundChecked, key_windowBackgroundWhite);
        fallbackKeys.put(key_switchTrackBlue, key_switchTrack);
        fallbackKeys.put(key_switchTrackBlueChecked, key_switchTrackChecked);
        fallbackKeys.put(key_switchTrackBlueThumb, key_windowBackgroundWhite);
        fallbackKeys.put(key_switchTrackBlueThumbChecked, key_windowBackgroundWhite);
        fallbackKeys.put(key_windowBackgroundCheckText, key_windowBackgroundWhiteBlackText);
        fallbackKeys.put(key_contextProgressInner4, key_contextProgressInner1);
        fallbackKeys.put(key_contextProgressOuter4, key_contextProgressOuter1);
        fallbackKeys.put(key_switchTrackBlueSelector, key_listSelector);
        fallbackKeys.put(key_switchTrackBlueSelectorChecked, key_listSelector);
        fallbackKeys.put(key_chat_emojiBottomPanelIcon, key_chat_emojiPanelIcon);
        fallbackKeys.put(key_chat_emojiSearchIcon, key_chat_emojiPanelIcon);
        fallbackKeys.put(key_chat_emojiPanelStickerSetNameHighlight, key_windowBackgroundWhiteBlueText4);
        fallbackKeys.put(key_chat_emojiPanelStickerPackSelectorLine, key_chat_emojiPanelIconSelected);
        fallbackKeys.put(key_sharedMedia_actionMode, key_actionBarDefault);
        fallbackKeys.put(key_sheet_scrollUp, key_chat_emojiPanelStickerPackSelector);
        fallbackKeys.put(key_sheet_other, key_player_actionBarItems);
        fallbackKeys.put(key_dialogSearchBackground, key_chat_emojiPanelStickerPackSelector);
        fallbackKeys.put(key_dialogSearchHint, key_chat_emojiPanelIcon);
        fallbackKeys.put(key_dialogSearchIcon, key_chat_emojiPanelIcon);
        fallbackKeys.put(key_dialogSearchText, key_windowBackgroundWhiteBlackText);
        fallbackKeys.put(key_dialogFloatingButton, key_dialogRoundCheckBox);
        fallbackKeys.put(key_dialogFloatingButtonPressed, key_dialogRoundCheckBox);
        fallbackKeys.put(key_dialogFloatingIcon, key_dialogRoundCheckBoxCheck);
        fallbackKeys.put(key_dialogShadowLine, key_chat_emojiPanelShadowLine);
        fallbackKeys.put(key_actionBarDefaultArchived, key_actionBarDefault);
        fallbackKeys.put(key_actionBarDefaultArchivedSelector, key_actionBarDefaultSelector);
        fallbackKeys.put(key_actionBarDefaultArchivedIcon, key_actionBarDefaultIcon);
        fallbackKeys.put(key_actionBarDefaultArchivedTitle, key_actionBarDefaultTitle);
        fallbackKeys.put(key_actionBarDefaultArchivedSearch, key_actionBarDefaultSearch);
        fallbackKeys.put(key_actionBarDefaultArchivedSearchPlaceholder, key_actionBarDefaultSearchPlaceholder);
        fallbackKeys.put(key_chats_message_threeLines, key_chats_message);
        fallbackKeys.put(key_chats_nameMessage_threeLines, key_chats_nameMessage);
        fallbackKeys.put(key_chats_nameArchived, key_chats_name);
        fallbackKeys.put(key_chats_nameMessageArchived, key_chats_nameMessage);
        fallbackKeys.put(key_chats_nameMessageArchived_threeLines, key_chats_nameMessage);
        fallbackKeys.put(key_chats_messageArchived, key_chats_message);
        fallbackKeys.put(key_avatar_backgroundArchived, key_chats_unreadCounterMuted);
        fallbackKeys.put(key_avatar_backgroundArchivedHidden, key_chats_unreadCounterMuted);
        fallbackKeys.put(key_chats_archiveBackground, key_chats_actionBackground);
        fallbackKeys.put(key_chats_archivePinBackground, key_chats_unreadCounterMuted);
        fallbackKeys.put(key_chats_archiveIcon, key_chats_actionIcon);
        fallbackKeys.put(key_chats_archiveText, key_chats_actionIcon);
        fallbackKeys.put(key_actionBarDefaultSubmenuItemIcon, key_dialogIcon);
        fallbackKeys.put(key_checkboxDisabled, key_chats_unreadCounterMuted);
        fallbackKeys.put(key_chat_status, key_actionBarDefaultSubtitle);
        fallbackKeys.put(key_chat_inGreenCall, key_calls_callReceivedGreenIcon);
        fallbackKeys.put(key_chat_inRedCall, key_calls_callReceivedRedIcon);
        fallbackKeys.put(key_chat_outGreenCall, key_calls_callReceivedGreenIcon);
        fallbackKeys.put(key_actionBarTabActiveText, key_actionBarDefaultTitle);
        fallbackKeys.put(key_actionBarTabUnactiveText, key_actionBarDefaultSubtitle);
        fallbackKeys.put(key_actionBarTabLine, key_actionBarDefaultTitle);
        fallbackKeys.put(key_actionBarTabSelector, key_actionBarDefaultSelector);
        fallbackKeys.put(key_profile_status, key_avatar_subtitleInProfileBlue);
        fallbackKeys.put(key_chats_menuTopBackgroundCats, key_avatar_backgroundActionBarBlue);
        fallbackKeys.put(key_chat_messagePanelSendPressed, key_chat_messagePanelVoicePressed);
        fallbackKeys.put(key_chat_attachPermissionImage, key_dialogTextBlack);
        fallbackKeys.put(key_chat_attachPermissionMark, key_chat_sentError);
        fallbackKeys.put(key_chat_attachPermissionText, key_dialogTextBlack);
        fallbackKeys.put(key_chat_attachEmptyImage, key_emptyListPlaceholder);
        fallbackKeys.put(key_actionBarBrowser, key_actionBarDefault);
        fallbackKeys.put(key_chats_sentReadCheck, key_chats_sentCheck);
        fallbackKeys.put(key_chat_outSentCheckRead, key_chat_outSentCheck);
        fallbackKeys.put(key_chat_outSentCheckReadSelected, key_chat_outSentCheckSelected);
        fallbackKeys.put(key_walletDefaultBackground, key_actionBarDefault);
        fallbackKeys.put(key_walletHoloBlueLight, key_windowBackgroundWhite);
        fallbackKeys.put(key_profileBottomBackgroundGray, key_windowBackgroundWhite);
        fallbackKeys.put(key_profileBtnBackgroundGray, key_windowBackgroundGray);
        fallbackKeys.put(key_profileBtnBackgroundBlue, key_windowBackgroundGray);
        fallbackKeys.put(key_themeCheckBoxUnchecked, key_windowBackgroundWhiteGrayText5);
        fallbackKeys.put(key_themeCheckBoxChecked, key_windowBackgroundWhiteBlueButton);
        fallbackKeys.put(key_themeCheckBoxDisabled, key_checkboxDisabled);
        fallbackKeys.put(key_searchview_solidColor, key_windowBackgroundWhite);
        fallbackKeys.put(key_searchview_strokeColor, key_windowBackgroundWhite);
        themeAccentExclusionKeys.addAll(Arrays.asList(keys_avatar_background));
        themeAccentExclusionKeys.addAll(Arrays.asList(keys_avatar_nameInMessage));
        themeAccentExclusionKeys.add(key_chat_attachFileBackground);
        themeAccentExclusionKeys.add(key_chat_attachGalleryBackground);
        themes = new ArrayList<>();
        otherThemes = new ArrayList<>();
        themesDict = new HashMap<>();
        currentColorsNoAccent = new HashMap<>();
        currentColors = new HashMap<>();
        ThemeInfo themeInfo = new ThemeInfo();
        themeInfo.name = "Default";
        themeInfo.previewBackgroundColor = -3155485;
        themeInfo.previewInColor = -1;
        themeInfo.previewOutColor = -983328;
        themeInfo.sortIndex = 0;
        ArrayList<ThemeInfo> arrayList = themes;
        defaultTheme = themeInfo;
        currentTheme = themeInfo;
        currentDayTheme = themeInfo;
        arrayList.add(themeInfo);
        themesDict.put("Default", defaultTheme);
        ThemeInfo themeInfo2 = new ThemeInfo();
        themeInfo2.name = "Blue";
        themeInfo2.assetName = "bluebubbles.attheme";
        themeInfo2.previewBackgroundColor = -6963476;
        themeInfo2.previewInColor = -1;
        themeInfo2.previewOutColor = -3086593;
        themeInfo2.sortIndex = 1;
        themeInfo2.setAccentColorOptions(new int[]{-13464881, -12342073, -11359164, -3317869, -2981834, -8165684, -3256745, -2904512, -8681301});
        themes.add(themeInfo2);
        themesDict.put("Blue", themeInfo2);
        ThemeInfo themeInfo3 = new ThemeInfo();
        themeInfo3.name = "Dark Blue";
        themeInfo3.assetName = "darkblue.attheme";
        themeInfo3.previewBackgroundColor = -10523006;
        themeInfo3.previewInColor = -9009508;
        themeInfo3.previewOutColor = -8214301;
        themeInfo3.sortIndex = 2;
        themeInfo3.setAccentColorOptions(new int[]{-13203974, -12138259, -11880383, -1344335, -1142742, -6127120, -2931932, -1131212, -8417365, -13270557});
        themes.add(themeInfo3);
        HashMap<String, ThemeInfo> map3 = themesDict;
        currentNightTheme = themeInfo3;
        map3.put("Dark Blue", themeInfo3);
        if (BuildVars.DEBUG_VERSION) {
            ThemeInfo themeInfo4 = new ThemeInfo();
            themeInfo4.name = "Graphite";
            themeInfo4.assetName = "graphite.attheme";
            themeInfo4.previewBackgroundColor = -8749431;
            themeInfo4.previewInColor = -6775901;
            themeInfo4.previewOutColor = -5980167;
            themeInfo4.sortIndex = 3;
            themes.add(themeInfo4);
            themesDict.put("Graphite", themeInfo4);
        }
        ThemeInfo themeInfo5 = new ThemeInfo();
        themeInfo5.name = "Arctic Blue";
        themeInfo5.assetName = "arctic.attheme";
        themeInfo5.previewBackgroundColor = -1;
        themeInfo5.previewInColor = -1315084;
        themeInfo5.previewOutColor = -8604930;
        themeInfo5.sortIndex = 4;
        themeInfo5.setAccentColorOptions(new int[]{-13332245, -12342073, -11359164, -3317869, -2981834, -8165684, -3256745, -2904512, -8681301});
        themes.add(themeInfo5);
        themesDict.put("Arctic Blue", themeInfo5);
        SharedPreferences preferences = ApplicationLoader.applicationContext.getSharedPreferences("themeconfig", 0);
        String themesString = preferences.getString("themes2", null);
        remoteThemesHash = preferences.getInt("remoteThemesHash", 0);
        lastLoadingThemesTime = preferences.getInt("lastLoadingThemesTime", 0);
        if (!TextUtils.isEmpty(themesString)) {
            try {
                JSONArray jsonArray = new JSONArray(themesString);
                for (int a = 0; a < jsonArray.length(); a++) {
                    ThemeInfo themeInfo6 = ThemeInfo.createWithJson(jsonArray.getJSONObject(a));
                    if (themeInfo6 != null) {
                        otherThemes.add(themeInfo6);
                        themes.add(themeInfo6);
                        themesDict.put(themeInfo6.getKey(), themeInfo6);
                    }
                }
            } catch (Exception e) {
                FileLog.e(e);
            }
        } else {
            String themesString2 = preferences.getString("themes", null);
            if (!TextUtils.isEmpty(themesString2)) {
                String[] themesArr = themesString2.split("&");
                for (String str : themesArr) {
                    ThemeInfo themeInfo7 = ThemeInfo.createWithString(str);
                    if (themeInfo7 != null) {
                        otherThemes.add(themeInfo7);
                        themes.add(themeInfo7);
                        themesDict.put(themeInfo7.getKey(), themeInfo7);
                    }
                }
            }
            saveOtherThemes(true);
            preferences.edit().remove("themes").commit();
        }
        sortThemes();
        ThemeInfo applyingTheme = null;
        try {
            ThemeInfo themeDarkBlue = themesDict.get("Dark Blue");
            SharedPreferences preferences2 = MessagesController.getGlobalMainSettings();
            String theme = preferences2.getString("theme", null);
            if ("Dark".equals(theme)) {
                applyingTheme = themeDarkBlue;
                themeDarkBlue.setAccentColor(-13270557);
            } else if (theme != null) {
                applyingTheme = themesDict.get(theme);
            }
            String theme2 = preferences2.getString("nighttheme", null);
            if ("Dark".equals(theme2)) {
                currentNightTheme = themeDarkBlue;
                themeDarkBlue.setAccentColor(-13270557);
            } else if (theme2 != null && (t = themesDict.get(theme2)) != null) {
                currentNightTheme = t;
            }
            for (ThemeInfo info : themesDict.values()) {
                if (info.assetName != null && info.accentBaseColor != 0) {
                    info.setAccentColor(preferences2.getInt("accent_for_" + info.assetName, info.accentColor));
                }
            }
            selectedAutoNightType = preferences2.getInt("selectedAutoNightType", 0);
            autoNightScheduleByLocation = preferences2.getBoolean("autoNightScheduleByLocation", false);
            autoNightBrighnessThreshold = preferences2.getFloat("autoNightBrighnessThreshold", 0.25f);
            autoNightDayStartTime = preferences2.getInt("autoNightDayStartTime", 1320);
            autoNightDayEndTime = preferences2.getInt("autoNightDayEndTime", 480);
            autoNightSunsetTime = preferences2.getInt("autoNightSunsetTime", 1320);
            autoNightSunriseTime = preferences2.getInt("autoNightSunriseTime", 480);
            autoNightCityName = preferences2.getString("autoNightCityName", "");
            long val = preferences2.getLong("autoNightLocationLatitude3", OkHttpUtils.DEFAULT_MILLISECONDS);
            if (val != OkHttpUtils.DEFAULT_MILLISECONDS) {
                autoNightLocationLatitude = Double.longBitsToDouble(val);
            } else {
                autoNightLocationLatitude = 10000.0d;
            }
            long val2 = preferences2.getLong("autoNightLocationLongitude3", OkHttpUtils.DEFAULT_MILLISECONDS);
            if (val2 != OkHttpUtils.DEFAULT_MILLISECONDS) {
                autoNightLocationLongitude = Double.longBitsToDouble(val2);
            } else {
                autoNightLocationLongitude = 10000.0d;
            }
            autoNightLastSunCheckDay = preferences2.getInt("autoNightLastSunCheckDay", -1);
        } catch (Exception e2) {
            FileLog.e(e2);
        }
        if (applyingTheme == null) {
            applyingTheme = defaultTheme;
        } else {
            currentDayTheme = applyingTheme;
        }
        applyTheme(applyingTheme, false, false, false);
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.actionbar.-$$Lambda$bRse6ibcjE0rjB1ORE0rL4q_oI4
            @Override // java.lang.Runnable
            public final void run() {
                Theme.checkAutoNightThemeConditions();
            }
        });
        ambientSensorListener = new SensorEventListener() { // from class: im.uwrkaxlmjj.ui.actionbar.Theme.7
            @Override // android.hardware.SensorEventListener
            public void onSensorChanged(SensorEvent event) {
                float lux = event.values[0];
                if (lux <= 0.0f) {
                    lux = 0.1f;
                }
                if (ApplicationLoader.mainInterfacePaused || !ApplicationLoader.isScreenOn) {
                    return;
                }
                if (lux > Theme.MAXIMUM_LUX_BREAKPOINT) {
                    float unused = Theme.lastBrightnessValue = 1.0f;
                } else {
                    float unused2 = Theme.lastBrightnessValue = ((float) Math.ceil((Math.log(lux) * 9.932299613952637d) + 27.05900001525879d)) / 100.0f;
                }
                if (Theme.lastBrightnessValue > Theme.autoNightBrighnessThreshold) {
                    if (Theme.switchNightRunnableScheduled) {
                        boolean unused3 = Theme.switchNightRunnableScheduled = false;
                        AndroidUtilities.cancelRunOnUIThread(Theme.switchNightBrightnessRunnable);
                    }
                    if (!Theme.switchDayRunnableScheduled) {
                        boolean unused4 = Theme.switchDayRunnableScheduled = true;
                        AndroidUtilities.runOnUIThread(Theme.switchDayBrightnessRunnable, Theme.getAutoNightSwitchThemeDelay());
                        return;
                    }
                    return;
                }
                if (!MediaController.getInstance().isRecordingOrListeningByProximity()) {
                    if (Theme.switchDayRunnableScheduled) {
                        boolean unused5 = Theme.switchDayRunnableScheduled = false;
                        AndroidUtilities.cancelRunOnUIThread(Theme.switchDayBrightnessRunnable);
                    }
                    if (!Theme.switchNightRunnableScheduled) {
                        boolean unused6 = Theme.switchNightRunnableScheduled = true;
                        AndroidUtilities.runOnUIThread(Theme.switchNightBrightnessRunnable, Theme.getAutoNightSwitchThemeDelay());
                    }
                }
            }

            @Override // android.hardware.SensorEventListener
            public void onAccuracyChanged(Sensor sensor, int accuracy) {
            }
        };
    }

    public static void saveAutoNightThemeConfig() {
        SharedPreferences.Editor editor = MessagesController.getGlobalMainSettings().edit();
        editor.putInt("selectedAutoNightType", selectedAutoNightType);
        editor.putBoolean("autoNightScheduleByLocation", autoNightScheduleByLocation);
        editor.putFloat("autoNightBrighnessThreshold", autoNightBrighnessThreshold);
        editor.putInt("autoNightDayStartTime", autoNightDayStartTime);
        editor.putInt("autoNightDayEndTime", autoNightDayEndTime);
        editor.putInt("autoNightSunriseTime", autoNightSunriseTime);
        editor.putString("autoNightCityName", autoNightCityName);
        editor.putInt("autoNightSunsetTime", autoNightSunsetTime);
        editor.putLong("autoNightLocationLatitude3", Double.doubleToRawLongBits(autoNightLocationLatitude));
        editor.putLong("autoNightLocationLongitude3", Double.doubleToRawLongBits(autoNightLocationLongitude));
        editor.putInt("autoNightLastSunCheckDay", autoNightLastSunCheckDay);
        ThemeInfo themeInfo = currentNightTheme;
        if (themeInfo != null) {
            editor.putString("nighttheme", themeInfo.getKey());
        } else {
            editor.remove("nighttheme");
        }
        editor.commit();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static Drawable getStateDrawable(Drawable drawable, int index) {
        if (StateListDrawable_getStateDrawableMethod == null) {
            try {
                StateListDrawable_getStateDrawableMethod = StateListDrawable.class.getDeclaredMethod("getStateDrawable", Integer.TYPE);
            } catch (Throwable th) {
            }
        }
        Method method = StateListDrawable_getStateDrawableMethod;
        if (method == null) {
            return null;
        }
        try {
            return (Drawable) method.invoke(drawable, Integer.valueOf(index));
        } catch (Exception e) {
            return null;
        }
    }

    public static Drawable createEmojiIconSelectorDrawable(Context context, int resource, int defaultColor, int pressedColor) {
        Resources resources = context.getResources();
        Drawable defaultDrawable = resources.getDrawable(resource).mutate();
        if (defaultColor != 0) {
            defaultDrawable.setColorFilter(new PorterDuffColorFilter(defaultColor, PorterDuff.Mode.MULTIPLY));
        }
        Drawable pressedDrawable = resources.getDrawable(resource).mutate();
        if (pressedColor != 0) {
            pressedDrawable.setColorFilter(new PorterDuffColorFilter(pressedColor, PorterDuff.Mode.MULTIPLY));
        }
        StateListDrawable stateListDrawable = new StateListDrawable() { // from class: im.uwrkaxlmjj.ui.actionbar.Theme.3
            @Override // android.graphics.drawable.DrawableContainer
            public boolean selectDrawable(int index) {
                if (Build.VERSION.SDK_INT < 21) {
                    Drawable drawable = Theme.getStateDrawable(this, index);
                    ColorFilter colorFilter3 = null;
                    if (drawable instanceof BitmapDrawable) {
                        colorFilter3 = ((BitmapDrawable) drawable).getPaint().getColorFilter();
                    } else if (drawable instanceof NinePatchDrawable) {
                        colorFilter3 = ((NinePatchDrawable) drawable).getPaint().getColorFilter();
                    }
                    boolean result = super.selectDrawable(index);
                    if (colorFilter3 != null) {
                        drawable.setColorFilter(colorFilter3);
                    }
                    return result;
                }
                return super.selectDrawable(index);
            }
        };
        stateListDrawable.setEnterFadeDuration(1);
        stateListDrawable.setExitFadeDuration(ItemTouchHelper.Callback.DEFAULT_DRAG_ANIMATION_DURATION);
        stateListDrawable.addState(new int[]{android.R.attr.state_selected}, pressedDrawable);
        stateListDrawable.addState(new int[0], defaultDrawable);
        return stateListDrawable;
    }

    public static Drawable createEditTextDrawable(Context context, boolean alert) {
        Resources resources = context.getResources();
        Drawable defaultDrawable = resources.getDrawable(R.drawable.search_dark).mutate();
        defaultDrawable.setColorFilter(new PorterDuffColorFilter(getColor(alert ? key_dialogInputField : key_windowBackgroundWhiteInputField), PorterDuff.Mode.MULTIPLY));
        Drawable pressedDrawable = resources.getDrawable(R.drawable.search_dark_activated).mutate();
        pressedDrawable.setColorFilter(new PorterDuffColorFilter(getColor(alert ? key_dialogInputFieldActivated : key_windowBackgroundWhiteInputFieldActivated), PorterDuff.Mode.MULTIPLY));
        StateListDrawable stateListDrawable = new StateListDrawable() { // from class: im.uwrkaxlmjj.ui.actionbar.Theme.4
            @Override // android.graphics.drawable.DrawableContainer
            public boolean selectDrawable(int index) {
                if (Build.VERSION.SDK_INT < 21) {
                    Drawable drawable = Theme.getStateDrawable(this, index);
                    ColorFilter colorFilter3 = null;
                    if (drawable instanceof BitmapDrawable) {
                        colorFilter3 = ((BitmapDrawable) drawable).getPaint().getColorFilter();
                    } else if (drawable instanceof NinePatchDrawable) {
                        colorFilter3 = ((NinePatchDrawable) drawable).getPaint().getColorFilter();
                    }
                    boolean result = super.selectDrawable(index);
                    if (colorFilter3 != null) {
                        drawable.setColorFilter(colorFilter3);
                    }
                    return result;
                }
                return super.selectDrawable(index);
            }
        };
        stateListDrawable.addState(new int[]{android.R.attr.state_enabled, android.R.attr.state_focused}, pressedDrawable);
        stateListDrawable.addState(new int[]{android.R.attr.state_focused}, pressedDrawable);
        stateListDrawable.addState(StateSet.WILD_CARD, defaultDrawable);
        return stateListDrawable;
    }

    public static boolean canStartHolidayAnimation() {
        return canStartHolidayAnimation;
    }

    public static int getEventType() {
        Calendar calendar = Calendar.getInstance();
        calendar.setTimeInMillis(System.currentTimeMillis());
        int monthOfYear = calendar.get(2);
        int dayOfMonth = calendar.get(5);
        calendar.get(12);
        calendar.get(11);
        if ((monthOfYear != 11 || dayOfMonth < 24 || dayOfMonth > 31) && (monthOfYear != 0 || dayOfMonth != 1)) {
            return -1;
        }
        return 0;
    }

    /* JADX WARN: Removed duplicated region for block: B:21:0x005b  */
    /* JADX WARN: Removed duplicated region for block: B:23:0x005f  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static android.graphics.drawable.Drawable getCurrentHolidayDrawable() {
        /*
            long r0 = java.lang.System.currentTimeMillis()
            long r2 = im.uwrkaxlmjj.ui.actionbar.Theme.lastHolidayCheckTime
            long r0 = r0 - r2
            r2 = 60000(0xea60, double:2.9644E-319)
            int r4 = (r0 > r2 ? 1 : (r0 == r2 ? 0 : -1))
            if (r4 < 0) goto L80
            long r0 = java.lang.System.currentTimeMillis()
            im.uwrkaxlmjj.ui.actionbar.Theme.lastHolidayCheckTime = r0
            java.util.Calendar r0 = java.util.Calendar.getInstance()
            long r1 = java.lang.System.currentTimeMillis()
            r0.setTimeInMillis(r1)
            r1 = 2
            int r1 = r0.get(r1)
            r2 = 5
            int r2 = r0.get(r2)
            r3 = 12
            int r3 = r0.get(r3)
            r4 = 11
            int r5 = r0.get(r4)
            r6 = 1
            if (r1 != 0) goto L43
            if (r2 != r6) goto L43
            r7 = 10
            if (r3 > r7) goto L43
            if (r5 != 0) goto L43
            im.uwrkaxlmjj.ui.actionbar.Theme.canStartHolidayAnimation = r6
            goto L46
        L43:
            r7 = 0
            im.uwrkaxlmjj.ui.actionbar.Theme.canStartHolidayAnimation = r7
        L46:
            android.graphics.drawable.Drawable r7 = im.uwrkaxlmjj.ui.actionbar.Theme.dialogs_holidayDrawable
            if (r7 != 0) goto L80
            if (r1 != r4) goto L5b
            boolean r4 = im.uwrkaxlmjj.messenger.BuildVars.DEBUG_PRIVATE_VERSION
            r7 = 31
            if (r4 == 0) goto L55
            r4 = 29
            goto L57
        L55:
            r4 = 31
        L57:
            if (r2 < r4) goto L5b
            if (r2 <= r7) goto L5f
        L5b:
            if (r1 != 0) goto L80
            if (r2 != r6) goto L80
        L5f:
            android.content.Context r4 = im.uwrkaxlmjj.messenger.ApplicationLoader.applicationContext
            android.content.res.Resources r4 = r4.getResources()
            r6 = 2131231378(0x7f080292, float:1.8078835E38)
            android.graphics.drawable.Drawable r4 = r4.getDrawable(r6)
            im.uwrkaxlmjj.ui.actionbar.Theme.dialogs_holidayDrawable = r4
            r4 = 1077936128(0x40400000, float:3.0)
            int r4 = im.uwrkaxlmjj.messenger.AndroidUtilities.dp(r4)
            int r4 = -r4
            im.uwrkaxlmjj.ui.actionbar.Theme.dialogs_holidayDrawableOffsetX = r4
            r4 = 1065353216(0x3f800000, float:1.0)
            int r4 = im.uwrkaxlmjj.messenger.AndroidUtilities.dp(r4)
            int r4 = -r4
            im.uwrkaxlmjj.ui.actionbar.Theme.dialogs_holidayDrawableOffsetY = r4
        L80:
            android.graphics.drawable.Drawable r0 = im.uwrkaxlmjj.ui.actionbar.Theme.dialogs_holidayDrawable
            return r0
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.ui.actionbar.Theme.getCurrentHolidayDrawable():android.graphics.drawable.Drawable");
    }

    public static int getCurrentHolidayDrawableXOffset() {
        return dialogs_holidayDrawableOffsetX;
    }

    public static int getCurrentHolidayDrawableYOffset() {
        return dialogs_holidayDrawableOffsetY;
    }

    public static Drawable createSimpleSelectorDrawable(Context context, int resource, int defaultColor, int pressedColor) {
        Resources resources = context.getResources();
        Drawable defaultDrawable = resources.getDrawable(resource).mutate();
        if (defaultColor != 0) {
            defaultDrawable.setColorFilter(new PorterDuffColorFilter(defaultColor, PorterDuff.Mode.MULTIPLY));
        }
        Drawable pressedDrawable = resources.getDrawable(resource).mutate();
        if (pressedColor != 0) {
            pressedDrawable.setColorFilter(new PorterDuffColorFilter(pressedColor, PorterDuff.Mode.MULTIPLY));
        }
        StateListDrawable stateListDrawable = new StateListDrawable() { // from class: im.uwrkaxlmjj.ui.actionbar.Theme.5
            @Override // android.graphics.drawable.DrawableContainer
            public boolean selectDrawable(int index) {
                if (Build.VERSION.SDK_INT < 21) {
                    Drawable drawable = Theme.getStateDrawable(this, index);
                    ColorFilter colorFilter3 = null;
                    if (drawable instanceof BitmapDrawable) {
                        colorFilter3 = ((BitmapDrawable) drawable).getPaint().getColorFilter();
                    } else if (drawable instanceof NinePatchDrawable) {
                        colorFilter3 = ((NinePatchDrawable) drawable).getPaint().getColorFilter();
                    }
                    boolean result = super.selectDrawable(index);
                    if (colorFilter3 != null) {
                        drawable.setColorFilter(colorFilter3);
                    }
                    return result;
                }
                return super.selectDrawable(index);
            }
        };
        stateListDrawable.addState(new int[]{android.R.attr.state_pressed}, pressedDrawable);
        stateListDrawable.addState(new int[]{android.R.attr.state_selected}, pressedDrawable);
        stateListDrawable.addState(StateSet.WILD_CARD, defaultDrawable);
        return stateListDrawable;
    }

    public static Drawable createCircleDrawable(int size, int color) {
        OvalShape ovalShape = new OvalShape();
        ovalShape.resize(size, size);
        ShapeDrawable defaultDrawable = new ShapeDrawable(ovalShape);
        defaultDrawable.getPaint().setColor(color);
        return defaultDrawable;
    }

    public static CombinedDrawable createCircleDrawableWithIcon(int size, int iconRes) {
        return createCircleDrawableWithIcon(size, iconRes, 0);
    }

    public static CombinedDrawable createCircleDrawableWithIcon(int size, int iconRes, int stroke) {
        Drawable drawable;
        if (iconRes != 0) {
            drawable = ApplicationLoader.applicationContext.getResources().getDrawable(iconRes).mutate();
        } else {
            drawable = null;
        }
        return createCircleDrawableWithIcon(size, drawable, stroke);
    }

    public static CombinedDrawable createCircleDrawableWithIcon(int size, Drawable drawable, int stroke) {
        OvalShape ovalShape = new OvalShape();
        ovalShape.resize(size, size);
        ShapeDrawable defaultDrawable = new ShapeDrawable(ovalShape);
        Paint paint = defaultDrawable.getPaint();
        paint.setColor(-1);
        if (stroke == 1) {
            paint.setStyle(Paint.Style.STROKE);
            paint.setStrokeWidth(AndroidUtilities.dp(2.0f));
        } else if (stroke == 2) {
            paint.setAlpha(0);
        }
        CombinedDrawable combinedDrawable = new CombinedDrawable(defaultDrawable, drawable);
        combinedDrawable.setCustomSize(size, size);
        return combinedDrawable;
    }

    public static Drawable createRoundRectDrawableWithIcon(int rad, int iconRes) {
        ShapeDrawable defaultDrawable = new ShapeDrawable(new RoundRectShape(new float[]{rad, rad, rad, rad, rad, rad, rad, rad}, null, null));
        defaultDrawable.getPaint().setColor(-1);
        Drawable drawable = ApplicationLoader.applicationContext.getResources().getDrawable(iconRes).mutate();
        return new CombinedDrawable(defaultDrawable, drawable);
    }

    public static void setCombinedDrawableColor(Drawable combinedDrawable, int color, boolean isIcon) {
        Drawable drawable;
        if (!(combinedDrawable instanceof CombinedDrawable)) {
            return;
        }
        if (isIcon) {
            drawable = ((CombinedDrawable) combinedDrawable).getIcon();
        } else {
            drawable = ((CombinedDrawable) combinedDrawable).getBackground();
        }
        if (drawable instanceof ColorDrawable) {
            ((ColorDrawable) drawable).setColor(color);
        } else {
            drawable.setColorFilter(new PorterDuffColorFilter(color, PorterDuff.Mode.MULTIPLY));
        }
    }

    public static ColorStateList createColorStateList(int normal, int selected) {
        int[] colors = {selected, normal};
        int[][] states = {new int[]{android.R.attr.state_selected, android.R.attr.state_enabled}, new int[0]};
        ColorStateList colorList = new ColorStateList(states, colors);
        return colorList;
    }

    public static Drawable createSimpleSelectorCircleDrawable(int size, int defaultColor, int pressedColor) {
        OvalShape ovalShape = new OvalShape();
        ovalShape.resize(size, size);
        ShapeDrawable defaultDrawable = new ShapeDrawable(ovalShape);
        defaultDrawable.getPaint().setColor(defaultColor);
        ShapeDrawable pressedDrawable = new ShapeDrawable(ovalShape);
        if (Build.VERSION.SDK_INT >= 21) {
            pressedDrawable.getPaint().setColor(-1);
            ColorStateList colorStateList = new ColorStateList(new int[][]{StateSet.WILD_CARD}, new int[]{pressedColor});
            return new RippleDrawable(colorStateList, defaultDrawable, pressedDrawable);
        }
        pressedDrawable.getPaint().setColor(pressedColor);
        StateListDrawable stateListDrawable = new StateListDrawable();
        stateListDrawable.addState(new int[]{android.R.attr.state_pressed}, pressedDrawable);
        stateListDrawable.addState(new int[]{android.R.attr.state_focused}, pressedDrawable);
        stateListDrawable.addState(StateSet.WILD_CARD, defaultDrawable);
        return stateListDrawable;
    }

    public static Drawable createRoundRectDrawable(float rad, int defaultColor) {
        ShapeDrawable defaultDrawable = new ShapeDrawable(new RoundRectShape(new float[]{rad, rad, rad, rad, rad, rad, rad, rad}, null, null));
        defaultDrawable.getPaint().setColor(defaultColor);
        return defaultDrawable;
    }

    public static Drawable createRoundRectDrawable(float lef_top, float right_top, float left_btm, float right_btm, int defaultColor) {
        ShapeDrawable defaultDrawable = new ShapeDrawable(new RoundRectShape(new float[]{lef_top, lef_top, right_top, right_top, right_btm, right_btm, left_btm, left_btm}, null, null));
        defaultDrawable.getPaint().setColor(defaultColor);
        return defaultDrawable;
    }

    public static Drawable createSimpleSelectorRoundRectDrawable(float rad, int defaultColor, int pressedColor) {
        return createSimpleSelectorRoundRectDrawable(rad, rad, rad, rad, defaultColor, pressedColor);
    }

    public static Drawable createSimpleSelectorRoundRectDrawable(float left_top, float right_top, float left_btm, float right_btm, int defaultColor, int pressedColor) {
        ShapeDrawable defaultDrawable = new ShapeDrawable(new RoundRectShape(new float[]{left_top, left_top, right_top, right_top, left_btm, left_btm, right_btm, right_btm}, null, null));
        defaultDrawable.getPaint().setColor(defaultColor);
        ShapeDrawable pressedDrawable = new ShapeDrawable(new RoundRectShape(new float[]{left_top, left_top, right_top, right_top, left_btm, left_btm, right_btm, right_btm}, null, null));
        pressedDrawable.getPaint().setColor(pressedColor);
        StateListDrawable stateListDrawable = new StateListDrawable();
        stateListDrawable.addState(new int[]{android.R.attr.state_pressed}, pressedDrawable);
        stateListDrawable.addState(new int[]{android.R.attr.state_selected}, pressedDrawable);
        stateListDrawable.addState(StateSet.WILD_CARD, defaultDrawable);
        return stateListDrawable;
    }

    public static Drawable getRoundRectSelectorDrawable(int color) {
        if (Build.VERSION.SDK_INT >= 21) {
            Drawable maskDrawable = createRoundRectDrawable(AndroidUtilities.dp(3.0f), -1);
            ColorStateList colorStateList = new ColorStateList(new int[][]{StateSet.WILD_CARD}, new int[]{419430400 | (16777215 & color)});
            return new RippleDrawable(colorStateList, null, maskDrawable);
        }
        StateListDrawable stateListDrawable = new StateListDrawable();
        stateListDrawable.addState(new int[]{android.R.attr.state_pressed}, createRoundRectDrawable(AndroidUtilities.dp(3.0f), (color & ViewCompat.MEASURED_SIZE_MASK) | 419430400));
        stateListDrawable.addState(new int[]{android.R.attr.state_selected}, createRoundRectDrawable(AndroidUtilities.dp(3.0f), 419430400 | (16777215 & color)));
        stateListDrawable.addState(StateSet.WILD_CARD, new ColorDrawable(0));
        return stateListDrawable;
    }

    public static Drawable createSelectorWithBackgroundDrawable(int backgroundColor, int color) {
        if (Build.VERSION.SDK_INT >= 21) {
            Drawable maskDrawable = new ColorDrawable(backgroundColor);
            ColorStateList colorStateList = new ColorStateList(new int[][]{StateSet.WILD_CARD}, new int[]{color});
            return new RippleDrawable(colorStateList, new ColorDrawable(backgroundColor), maskDrawable);
        }
        StateListDrawable stateListDrawable = new StateListDrawable();
        stateListDrawable.addState(new int[]{android.R.attr.state_pressed}, new ColorDrawable(color));
        stateListDrawable.addState(new int[]{android.R.attr.state_selected}, new ColorDrawable(color));
        stateListDrawable.addState(StateSet.WILD_CARD, new ColorDrawable(backgroundColor));
        return stateListDrawable;
    }

    public static Drawable getSelectorDrawable(boolean whiteBackground) {
        return getSelectorDrawable(getColor(key_listSelector), whiteBackground);
    }

    public static Drawable getSelectorDrawable(int color, boolean whiteBackground) {
        if (whiteBackground) {
            if (Build.VERSION.SDK_INT >= 21) {
                Drawable maskDrawable = new ColorDrawable(-1);
                ColorStateList colorStateList = new ColorStateList(new int[][]{StateSet.WILD_CARD}, new int[]{color});
                return new RippleDrawable(colorStateList, new ColorDrawable(getColor(key_windowBackgroundWhite)), maskDrawable);
            }
            StateListDrawable stateListDrawable = new StateListDrawable();
            stateListDrawable.addState(new int[]{android.R.attr.state_pressed}, new ColorDrawable(color));
            stateListDrawable.addState(new int[]{android.R.attr.state_selected}, new ColorDrawable(color));
            stateListDrawable.addState(StateSet.WILD_CARD, new ColorDrawable(getColor(key_windowBackgroundWhite)));
            return stateListDrawable;
        }
        return createSelectorDrawable(color, 2);
    }

    public static Drawable getRoundRectSelectorDrawable(int radius, int color) {
        return getRoundRectSelectorDrawable(radius, radius, radius, radius, color);
    }

    public static Drawable getRoundRectSelectorDrawable(int lef_top, int right_top, int left_btm, int right_btm, int color) {
        if (Build.VERSION.SDK_INT >= 21) {
            Drawable maskDrawable = createRoundRectDrawable(lef_top, right_top, left_btm, right_btm, color);
            ColorStateList colorStateList = new ColorStateList(new int[][]{StateSet.WILD_CARD}, new int[]{getColor(key_listSelector)});
            return new RippleDrawable(colorStateList, maskDrawable, maskDrawable);
        }
        StateListDrawable stateListDrawable = new StateListDrawable();
        stateListDrawable.addState(new int[]{android.R.attr.state_pressed}, createRoundRectDrawable(lef_top, right_top, left_btm, right_btm, (color & ViewCompat.MEASURED_SIZE_MASK) | 419430400));
        stateListDrawable.addState(new int[]{android.R.attr.state_selected}, createRoundRectDrawable(lef_top, right_top, left_btm, right_btm, (color & ViewCompat.MEASURED_SIZE_MASK) | 419430400));
        stateListDrawable.addState(StateSet.WILD_CARD, createRoundRectDrawable(lef_top, right_top, left_btm, right_btm, color));
        return stateListDrawable;
    }

    public static Drawable createSelectorDrawable(int color) {
        return createSelectorDrawable(color, 1, -1);
    }

    public static Drawable createSelectorDrawable(int color, int maskType) {
        return createSelectorDrawable(color, maskType, -1);
    }

    public static Drawable createSelectorDrawable(int color, final int maskType, int radius) {
        if (Build.VERSION.SDK_INT >= 21) {
            Drawable maskDrawable = null;
            if ((maskType == 1 || maskType == 5) && Build.VERSION.SDK_INT >= 23) {
                maskDrawable = null;
            } else if (maskType == 1 || maskType == 3 || maskType == 4 || maskType == 5 || maskType == 6 || maskType == 7) {
                maskPaint.setColor(-1);
                maskDrawable = new Drawable() { // from class: im.uwrkaxlmjj.ui.actionbar.Theme.6
                    RectF rect;

                    @Override // android.graphics.drawable.Drawable
                    public void draw(Canvas canvas) {
                        int rad;
                        Rect bounds = getBounds();
                        int i = maskType;
                        if (i == 7) {
                            if (this.rect == null) {
                                this.rect = new RectF();
                            }
                            this.rect.set(bounds);
                            canvas.drawRoundRect(this.rect, AndroidUtilities.dp(6.0f), AndroidUtilities.dp(6.0f), Theme.maskPaint);
                            return;
                        }
                        if (i == 1 || i == 6) {
                            rad = AndroidUtilities.dp(20.0f);
                        } else if (i == 3) {
                            rad = Math.max(bounds.width(), bounds.height()) / 2;
                        } else {
                            int rad2 = bounds.left;
                            rad = (int) Math.ceil(Math.sqrt(((rad2 - bounds.centerX()) * (bounds.left - bounds.centerX())) + ((bounds.top - bounds.centerY()) * (bounds.top - bounds.centerY()))));
                        }
                        canvas.drawCircle(bounds.centerX(), bounds.centerY(), rad, Theme.maskPaint);
                    }

                    @Override // android.graphics.drawable.Drawable
                    public void setAlpha(int alpha) {
                    }

                    @Override // android.graphics.drawable.Drawable
                    public void setColorFilter(ColorFilter colorFilter3) {
                    }

                    @Override // android.graphics.drawable.Drawable
                    public int getOpacity() {
                        return 0;
                    }
                };
            } else if (maskType == 2) {
                maskDrawable = new ColorDrawable(-1);
            }
            ColorStateList colorStateList = new ColorStateList(new int[][]{StateSet.WILD_CARD}, new int[]{color});
            RippleDrawable rippleDrawable = new RippleDrawable(colorStateList, null, maskDrawable);
            if (Build.VERSION.SDK_INT >= 23) {
                if (maskType == 1) {
                    rippleDrawable.setRadius(radius <= 0 ? AndroidUtilities.dp(20.0f) : radius);
                } else if (maskType == 5) {
                    rippleDrawable.setRadius(-1);
                }
            }
            return rippleDrawable;
        }
        StateListDrawable stateListDrawable = new StateListDrawable();
        stateListDrawable.addState(new int[]{android.R.attr.state_pressed}, new ColorDrawable(color));
        stateListDrawable.addState(new int[]{android.R.attr.state_selected}, new ColorDrawable(color));
        stateListDrawable.addState(StateSet.WILD_CARD, new ColorDrawable(0));
        return stateListDrawable;
    }

    public static void applyPreviousTheme() {
        ThemeInfo themeInfo;
        if (previousTheme == null) {
            return;
        }
        if (isWallpaperMotionPrev != null) {
            SharedPreferences.Editor editor = MessagesController.getGlobalMainSettings().edit();
            boolean zBooleanValue = isWallpaperMotionPrev.booleanValue();
            isWallpaperMotion = zBooleanValue;
            editor.putBoolean("selectedBackgroundMotion", zBooleanValue);
            editor.commit();
        }
        if (isInNigthMode && (themeInfo = currentNightTheme) != null) {
            applyTheme(themeInfo, true, false, true);
        } else {
            applyTheme(previousTheme, true, false, false);
        }
        previousTheme = null;
        checkAutoNightThemeConditions();
    }

    private static void sortThemes() {
        Collections.sort(themes, new Comparator() { // from class: im.uwrkaxlmjj.ui.actionbar.-$$Lambda$Theme$RfO7CdhBJ5Zt0JrAprDb1VKvAWI
            @Override // java.util.Comparator
            public final int compare(Object obj, Object obj2) {
                return Theme.lambda$sortThemes$0((Theme.ThemeInfo) obj, (Theme.ThemeInfo) obj2);
            }
        });
    }

    static /* synthetic */ int lambda$sortThemes$0(ThemeInfo o1, ThemeInfo o2) {
        if (o1.pathToFile == null && o1.assetName == null) {
            return -1;
        }
        if (o2.pathToFile == null && o2.assetName == null) {
            return 1;
        }
        return o1.name.compareTo(o2.name);
    }

    public static void applyThemeTemporary(ThemeInfo themeInfo) {
        previousTheme = getCurrentTheme();
        applyTheme(themeInfo, false, false, false);
    }

    public static ThemeInfo fillThemeValues(File file, String themeName, TLRPC.TL_theme theme) {
        String[] modes;
        try {
            ThemeInfo themeInfo = new ThemeInfo();
            themeInfo.name = themeName;
            themeInfo.info = theme;
            themeInfo.pathToFile = file.getAbsolutePath();
            themeInfo.account = UserConfig.selectedAccount;
            String[] wallpaperLink = new String[1];
            getThemeFileValues(new File(themeInfo.pathToFile), null, wallpaperLink);
            if (!TextUtils.isEmpty(wallpaperLink[0])) {
                String ling = wallpaperLink[0];
                themeInfo.pathToWallpaper = new File(ApplicationLoader.getFilesDirFixed(), Utilities.MD5(ling) + ".wp").getAbsolutePath();
                try {
                    Uri data = Uri.parse(ling);
                    themeInfo.slug = data.getQueryParameter("slug");
                    String mode = data.getQueryParameter("mode");
                    if (mode != null && (modes = mode.toLowerCase().split(" ")) != null && modes.length > 0) {
                        for (int a = 0; a < modes.length; a++) {
                            if ("blur".equals(modes[a])) {
                                themeInfo.isBlured = true;
                            } else if ("motion".equals(modes[a])) {
                                themeInfo.isMotion = true;
                            }
                        }
                    }
                } catch (Throwable e) {
                    FileLog.e(e);
                }
            } else {
                themedWallpaperLink = null;
            }
            return themeInfo;
        } catch (Exception e2) {
            FileLog.e(e2);
            return null;
        }
    }

    public static ThemeInfo applyThemeFile(File file, String themeName, TLRPC.TL_theme theme, boolean temporary) {
        String key;
        File finalFile;
        try {
            if (!themeName.toLowerCase().endsWith(".attheme")) {
                themeName = themeName + ".attheme";
            }
            if (temporary) {
                NotificationCenter.getGlobalInstance().postNotificationName(NotificationCenter.goingToPreviewTheme, new Object[0]);
                ThemeInfo themeInfo = new ThemeInfo();
                themeInfo.name = themeName;
                themeInfo.info = theme;
                themeInfo.pathToFile = file.getAbsolutePath();
                themeInfo.account = UserConfig.selectedAccount;
                applyThemeTemporary(themeInfo);
                return themeInfo;
            }
            if (theme != null) {
                key = "remote" + theme.id;
                finalFile = new File(ApplicationLoader.getFilesDirFixed(), key + ".attheme");
            } else {
                key = themeName;
                finalFile = new File(ApplicationLoader.getFilesDirFixed(), key);
            }
            if (!AndroidUtilities.copyFile(file, finalFile)) {
                applyPreviousTheme();
                return null;
            }
            previousTheme = null;
            ThemeInfo themeInfo2 = themesDict.get(key);
            if (themeInfo2 == null) {
                themeInfo2 = new ThemeInfo();
                themeInfo2.name = themeName;
                themeInfo2.account = UserConfig.selectedAccount;
                themes.add(themeInfo2);
                otherThemes.add(themeInfo2);
                sortThemes();
            } else {
                themesDict.remove(key);
            }
            themeInfo2.info = theme;
            themeInfo2.pathToFile = finalFile.getAbsolutePath();
            themesDict.put(themeInfo2.getKey(), themeInfo2);
            saveOtherThemes(true);
            applyTheme(themeInfo2, true, true, false);
            return themeInfo2;
        } catch (Exception e) {
            FileLog.e(e);
            return null;
        }
    }

    public static void applyTheme(ThemeInfo themeInfo) {
        applyTheme(themeInfo, true, true, false);
    }

    public static void applyTheme(ThemeInfo themeInfo, boolean nightTheme) {
        applyTheme(themeInfo, true, true, nightTheme);
    }

    /* JADX WARN: Removed duplicated region for block: B:28:0x0061 A[Catch: Exception -> 0x0047, TryCatch #3 {Exception -> 0x0047, blocks: (B:12:0x001a, B:17:0x0023, B:19:0x0030, B:20:0x0033, B:21:0x0036, B:26:0x0050, B:28:0x0061, B:29:0x0064, B:33:0x006f, B:39:0x0092), top: B:119:0x001a }] */
    /* JADX WARN: Removed duplicated region for block: B:33:0x006f A[Catch: Exception -> 0x0047, TRY_ENTER, TRY_LEAVE, TryCatch #3 {Exception -> 0x0047, blocks: (B:12:0x001a, B:17:0x0023, B:19:0x0030, B:20:0x0033, B:21:0x0036, B:26:0x0050, B:28:0x0061, B:29:0x0064, B:33:0x006f, B:39:0x0092), top: B:119:0x001a }] */
    /* JADX WARN: Removed duplicated region for block: B:35:0x0078 A[Catch: Exception -> 0x01f3, TRY_ENTER, TryCatch #4 {Exception -> 0x01f3, blocks: (B:9:0x0011, B:31:0x0068, B:36:0x0085, B:42:0x0098, B:44:0x00a2, B:35:0x0078), top: B:120:0x0011 }] */
    /* JADX WARN: Removed duplicated region for block: B:39:0x0092 A[Catch: Exception -> 0x0047, TRY_ENTER, TRY_LEAVE, TryCatch #3 {Exception -> 0x0047, blocks: (B:12:0x001a, B:17:0x0023, B:19:0x0030, B:20:0x0033, B:21:0x0036, B:26:0x0050, B:28:0x0061, B:29:0x0064, B:33:0x006f, B:39:0x0092), top: B:119:0x001a }] */
    /* JADX WARN: Removed duplicated region for block: B:41:0x0097  */
    /* JADX WARN: Removed duplicated region for block: B:44:0x00a2 A[Catch: Exception -> 0x01f3, TRY_LEAVE, TryCatch #4 {Exception -> 0x01f3, blocks: (B:9:0x0011, B:31:0x0068, B:36:0x0085, B:42:0x0098, B:44:0x00a2, B:35:0x0078), top: B:120:0x0011 }] */
    /* JADX WARN: Removed duplicated region for block: B:94:0x01dd A[Catch: Exception -> 0x01f1, TryCatch #6 {Exception -> 0x01f1, blocks: (B:96:0x01e3, B:98:0x01e7, B:100:0x01eb, B:101:0x01ed, B:92:0x01d9, B:94:0x01dd), top: B:124:0x0018 }] */
    /* JADX WARN: Removed duplicated region for block: B:98:0x01e7 A[Catch: Exception -> 0x01f1, TryCatch #6 {Exception -> 0x01f1, blocks: (B:96:0x01e3, B:98:0x01e7, B:100:0x01eb, B:101:0x01ed, B:92:0x01d9, B:94:0x01dd), top: B:124:0x0018 }] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    private static void applyTheme(im.uwrkaxlmjj.ui.actionbar.Theme.ThemeInfo r20, boolean r21, boolean r22, boolean r23) {
        /*
            Method dump skipped, instruction units count: 524
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.ui.actionbar.Theme.applyTheme(im.uwrkaxlmjj.ui.actionbar.Theme$ThemeInfo, boolean, boolean, boolean):void");
    }

    private static void refreshThemeColors() {
        String fallbackKey;
        currentColors.clear();
        currentColors.putAll(currentColorsNoAccent);
        ThemeInfo themeInfo = currentTheme;
        if (themeInfo.accentColor != 0 && themeInfo.accentBaseColor != 0 && themeInfo.accentColor != themeInfo.accentBaseColor) {
            HashSet<String> keys = new HashSet<>(currentColorsNoAccent.keySet());
            keys.addAll(defaultColors.keySet());
            keys.removeAll(themeAccentExclusionKeys);
            for (String key : keys) {
                Integer color = currentColorsNoAccent.get(key);
                if (color != null || (fallbackKey = fallbackKeys.get(key)) == null || currentColorsNoAccent.get(fallbackKey) == null) {
                    if (color == null) {
                        color = defaultColors.get(key);
                    }
                    int newColor = changeColorAccent(themeInfo.accentBaseColorHsv, themeInfo.accentColorHsv, color.intValue());
                    if (newColor != color.intValue()) {
                        currentColors.put(key, Integer.valueOf(newColor));
                    }
                }
            }
        }
        reloadWallpaper();
        applyCommonTheme();
        applyDialogsTheme();
        applyProfileTheme();
        applyChatTheme(false);
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.actionbar.-$$Lambda$Theme$VSEl1WQ_ifpDFpMUgLey6-3Lyxw
            @Override // java.lang.Runnable
            public final void run() {
                NotificationCenter.getGlobalInstance().postNotificationName(NotificationCenter.didSetNewTheme, false);
            }
        });
    }

    public static int changeColorAccent(ThemeInfo themeInfo, int accent, int color) {
        if (accent == 0 || themeInfo.accentBaseColor == 0 || accent == themeInfo.accentBaseColor) {
            return color;
        }
        Color.colorToHSV(accent, hsv);
        return changeColorAccent(themeInfo.accentBaseColorHsv, hsv, color);
    }

    public static int changeColorAccent(int color) {
        ThemeInfo themeInfo = currentTheme;
        return changeColorAccent(themeInfo, themeInfo.accentColor, color);
    }

    private static int changeColorAccent(float[] baseHsv, float[] accentHsv, int color) {
        float baseH = baseHsv[0];
        float baseS = baseHsv[1];
        float baseV = baseHsv[2];
        float accentH = accentHsv[0];
        float accentS = accentHsv[1];
        float accentV = accentHsv[2];
        Color.colorToHSV(color, hsv);
        float[] fArr = hsv;
        float colorH = fArr[0];
        float colorS = fArr[1];
        float colorV = fArr[2];
        float diffH = Math.min(Math.abs(colorH - baseH), Math.abs((colorH - baseH) - 360.0f));
        if (diffH > 30.0f) {
            return color;
        }
        float dist = Math.min((1.5f * colorS) / baseS, 1.0f);
        float[] fArr2 = hsv;
        fArr2[0] = (colorH + accentH) - baseH;
        fArr2[1] = (colorS * accentS) / baseS;
        fArr2[2] = ((1.0f - dist) + ((dist * accentV) / baseV)) * colorV;
        return Color.HSVToColor(Color.alpha(color), hsv);
    }

    public static void applyCurrentThemeAccent(int accent) {
        currentTheme.setAccentColor(accent);
        refreshThemeColors();
    }

    public static void saveThemeAccent(ThemeInfo themeInfo, int accent) {
        if (themeInfo.assetName != null) {
            MessagesController.getGlobalMainSettings().edit().putInt("accent_for_" + themeInfo.assetName, accent).commit();
            themeInfo.setAccentColor(accent);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static void saveOtherThemes(boolean full) {
        SharedPreferences preferences = ApplicationLoader.applicationContext.getSharedPreferences("themeconfig", 0);
        SharedPreferences.Editor editor = preferences.edit();
        if (full) {
            JSONArray array = new JSONArray();
            for (int a = 0; a < otherThemes.size(); a++) {
                JSONObject jsonObject = otherThemes.get(a).getSaveJson();
                if (jsonObject != null) {
                    array.put(jsonObject);
                }
            }
            editor.putString("themes2", array.toString());
        }
        editor.putInt("remoteThemesHash", remoteThemesHash);
        editor.putInt("lastLoadingThemesTime", lastLoadingThemesTime);
        editor.putInt("lastLoadingCurrentThemeTime", lastLoadingCurrentThemeTime);
        editor.commit();
    }

    public static HashMap<String, Integer> getDefaultColors() {
        return defaultColors;
    }

    public static String getCurrentThemeName() {
        String text = currentDayTheme.getName();
        if (text.toLowerCase().endsWith(".attheme")) {
            return text.substring(0, text.lastIndexOf(46));
        }
        return text;
    }

    public static String getCurrentNightThemeName() {
        ThemeInfo themeInfo = currentNightTheme;
        if (themeInfo == null) {
            return "";
        }
        String text = themeInfo.getName();
        if (text.toLowerCase().endsWith(".attheme")) {
            return text.substring(0, text.lastIndexOf(46));
        }
        return text;
    }

    public static ThemeInfo getCurrentTheme() {
        ThemeInfo themeInfo = currentDayTheme;
        return themeInfo != null ? themeInfo : defaultTheme;
    }

    public static ThemeInfo getCurrentNightTheme() {
        return currentNightTheme;
    }

    public static boolean isCurrentThemeNight() {
        return currentTheme == currentNightTheme;
    }

    private static boolean isCurrentThemeDefault() {
        return currentTheme == defaultTheme;
    }

    public static boolean isThemeDefault(ThemeInfo themeInfo) {
        return themeInfo == defaultTheme;
    }

    public static boolean isThemeDefault() {
        return currentTheme == defaultTheme;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static long getAutoNightSwitchThemeDelay() {
        long newTime = SystemClock.elapsedRealtime();
        return Math.abs(lastThemeSwitchTime - newTime) >= 12000 ? 1800L : 12000L;
    }

    public static void setCurrentNightTheme(ThemeInfo theme) {
        boolean apply = currentTheme == currentNightTheme;
        currentNightTheme = theme;
        if (apply) {
            applyDayNightThemeMaybe(true);
        }
    }

    public static void checkAutoNightThemeConditions() {
        checkAutoNightThemeConditions(false);
    }

    public static void checkAutoNightThemeConditions(boolean force) {
        Sensor sensor;
        int timeStart;
        int day;
        if (previousTheme != null) {
            return;
        }
        if (force) {
            if (switchNightRunnableScheduled) {
                switchNightRunnableScheduled = false;
                AndroidUtilities.cancelRunOnUIThread(switchNightBrightnessRunnable);
            }
            if (switchDayRunnableScheduled) {
                switchDayRunnableScheduled = false;
                AndroidUtilities.cancelRunOnUIThread(switchDayBrightnessRunnable);
            }
        }
        if (selectedAutoNightType != 2) {
            if (switchNightRunnableScheduled) {
                switchNightRunnableScheduled = false;
                AndroidUtilities.cancelRunOnUIThread(switchNightBrightnessRunnable);
            }
            if (switchDayRunnableScheduled) {
                switchDayRunnableScheduled = false;
                AndroidUtilities.cancelRunOnUIThread(switchDayBrightnessRunnable);
            }
            if (lightSensorRegistered) {
                lastBrightnessValue = 1.0f;
                sensorManager.unregisterListener(ambientSensorListener, lightSensor);
                lightSensorRegistered = false;
                if (BuildVars.LOGS_ENABLED) {
                    FileLog.d("light sensor unregistered");
                }
            }
        }
        int switchToTheme = 0;
        int i = selectedAutoNightType;
        if (i == 1) {
            Calendar calendar = Calendar.getInstance();
            calendar.setTimeInMillis(System.currentTimeMillis());
            int time = (calendar.get(11) * 60) + calendar.get(12);
            if (autoNightScheduleByLocation) {
                int day2 = calendar.get(5);
                if (autoNightLastSunCheckDay != day2) {
                    double d = autoNightLocationLatitude;
                    if (d != 10000.0d) {
                        double d2 = autoNightLocationLongitude;
                        if (d2 != 10000.0d) {
                            int[] t = SunDate.calculateSunriseSunset(d, d2);
                            autoNightSunriseTime = t[0];
                            autoNightSunsetTime = t[1];
                            autoNightLastSunCheckDay = day2;
                            saveAutoNightThemeConfig();
                        }
                    }
                }
                timeStart = autoNightSunsetTime;
                day = autoNightSunriseTime;
            } else {
                timeStart = autoNightDayStartTime;
                day = autoNightDayEndTime;
            }
            switchToTheme = timeStart < day ? (timeStart > time || time > day) ? 1 : 2 : ((timeStart > time || time > 1440) && (time < 0 || time > day)) ? 1 : 2;
        } else if (i == 2) {
            if (lightSensor == null) {
                SensorManager sensorManager2 = (SensorManager) ApplicationLoader.applicationContext.getSystemService("sensor");
                sensorManager = sensorManager2;
                lightSensor = sensorManager2.getDefaultSensor(5);
            }
            if (!lightSensorRegistered && (sensor = lightSensor) != null) {
                sensorManager.registerListener(ambientSensorListener, sensor, 500000);
                lightSensorRegistered = true;
                if (BuildVars.LOGS_ENABLED) {
                    FileLog.d("light sensor registered");
                }
            }
            if (lastBrightnessValue <= autoNightBrighnessThreshold) {
                if (!switchNightRunnableScheduled) {
                    switchToTheme = 2;
                }
            } else if (!switchDayRunnableScheduled) {
                switchToTheme = 1;
            }
        } else if (i == 0) {
            switchToTheme = 1;
        }
        if (switchToTheme != 0) {
            applyDayNightThemeMaybe(switchToTheme == 2);
        }
        if (force) {
            lastThemeSwitchTime = 0L;
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static void applyDayNightThemeMaybe(boolean night) {
        if (previousTheme != null) {
            return;
        }
        if (night) {
            if (currentTheme != currentNightTheme) {
                isInNigthMode = true;
                lastThemeSwitchTime = SystemClock.elapsedRealtime();
                switchingNightTheme = true;
                NotificationCenter.getGlobalInstance().postNotificationName(NotificationCenter.needSetDayNightTheme, currentNightTheme, true);
                switchingNightTheme = false;
                return;
            }
            return;
        }
        if (currentTheme != currentDayTheme) {
            isInNigthMode = false;
            lastThemeSwitchTime = SystemClock.elapsedRealtime();
            switchingNightTheme = true;
            NotificationCenter.getGlobalInstance().postNotificationName(NotificationCenter.needSetDayNightTheme, currentDayTheme, true);
            switchingNightTheme = false;
        }
    }

    public static boolean deleteTheme(ThemeInfo themeInfo) {
        if (themeInfo.pathToFile == null) {
            return false;
        }
        boolean currentThemeDeleted = false;
        if (currentTheme == themeInfo) {
            applyTheme(defaultTheme, true, false, false);
            currentThemeDeleted = true;
        }
        if (themeInfo == currentNightTheme) {
            currentNightTheme = themesDict.get("Dark Blue");
        }
        themeInfo.removeObservers();
        otherThemes.remove(themeInfo);
        themesDict.remove(themeInfo.name);
        themes.remove(themeInfo);
        File file = new File(themeInfo.pathToFile);
        file.delete();
        saveOtherThemes(true);
        return currentThemeDeleted;
    }

    public static ThemeInfo createNewTheme(String name) throws Throwable {
        ThemeInfo newTheme = new ThemeInfo();
        newTheme.pathToFile = new File(ApplicationLoader.getFilesDirFixed(), "theme" + Utilities.random.nextLong() + ".attheme").getAbsolutePath();
        newTheme.name = name;
        newTheme.account = UserConfig.selectedAccount;
        saveCurrentTheme(newTheme, true, true, false);
        return newTheme;
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:106:0x02c4  */
    /* JADX WARN: Removed duplicated region for block: B:122:0x02ec A[Catch: Exception -> 0x02cb, TRY_ENTER, TRY_LEAVE, TryCatch #1 {Exception -> 0x02cb, blocks: (B:108:0x02c7, B:122:0x02ec), top: B:137:0x0185 }] */
    /* JADX WARN: Removed duplicated region for block: B:125:0x02f2  */
    /* JADX WARN: Removed duplicated region for block: B:143:0x0300 A[EXC_TOP_SPLITTER, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:163:? A[RETURN, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:164:? A[SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:68:0x01bf A[Catch: all -> 0x02db, Exception -> 0x02e2, TRY_LEAVE, TryCatch #11 {Exception -> 0x02e2, all -> 0x02db, blocks: (B:54:0x0185, B:66:0x01ae, B:68:0x01bf), top: B:137:0x0185 }] */
    /* JADX WARN: Removed duplicated region for block: B:85:0x022a A[Catch: all -> 0x02d2, Exception -> 0x02d7, TryCatch #12 {Exception -> 0x02d7, all -> 0x02d2, blocks: (B:94:0x027d, B:96:0x0289, B:97:0x02a2, B:99:0x02a8, B:100:0x02aa, B:82:0x0221, B:85:0x022a, B:87:0x0232, B:89:0x023b, B:92:0x0275), top: B:152:0x01bd }] */
    /* JADX WARN: Removed duplicated region for block: B:94:0x027d A[Catch: all -> 0x02d2, Exception -> 0x02d7, TryCatch #12 {Exception -> 0x02d7, all -> 0x02d2, blocks: (B:94:0x027d, B:96:0x0289, B:97:0x02a2, B:99:0x02a8, B:100:0x02aa, B:82:0x0221, B:85:0x022a, B:87:0x0232, B:89:0x023b, B:92:0x0275), top: B:152:0x01bd }] */
    /* JADX WARN: Type inference failed for: r21v11 */
    /* JADX WARN: Type inference failed for: r21v12, types: [int] */
    /* JADX WARN: Type inference failed for: r21v13 */
    /* JADX WARN: Type inference failed for: r21v14 */
    /* JADX WARN: Type inference failed for: r21v3 */
    /* JADX WARN: Type inference failed for: r21v4 */
    /* JADX WARN: Type inference failed for: r21v5 */
    /* JADX WARN: Type inference failed for: r21v6 */
    /* JADX WARN: Type inference failed for: r21v9 */
    /* JADX WARN: Type inference failed for: r2v1 */
    /* JADX WARN: Type inference failed for: r2v2 */
    /* JADX WARN: Type inference failed for: r2v5 */
    /* JADX WARN: Unsupported multi-entry loop pattern (BACK_EDGE: B:111:0x02cc -> B:136:0x02f0). Please report as a decompilation issue!!! */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static void saveCurrentTheme(im.uwrkaxlmjj.ui.actionbar.Theme.ThemeInfo r23, boolean r24, boolean r25, boolean r26) throws java.lang.Throwable {
        /*
            Method dump skipped, instruction units count: 781
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.ui.actionbar.Theme.saveCurrentTheme(im.uwrkaxlmjj.ui.actionbar.Theme$ThemeInfo, boolean, boolean, boolean):void");
    }

    public static void checkCurrentRemoteTheme(boolean force) {
        if (loadingCurrentTheme == 0) {
            if (!force && Math.abs((System.currentTimeMillis() / 1000) - ((long) lastLoadingCurrentThemeTime)) < 3600) {
                return;
            }
            int a = 0;
            while (a < 2) {
                final ThemeInfo themeInfo = a == 0 ? currentDayTheme : currentNightTheme;
                if (themeInfo != null && themeInfo.info != null && themeInfo.info.document != null && UserConfig.getInstance(themeInfo.account).isClientActivated()) {
                    loadingCurrentTheme++;
                    TLRPC.TL_account_getTheme req = new TLRPC.TL_account_getTheme();
                    req.document_id = themeInfo.info.document.id;
                    req.format = "android";
                    TLRPC.TL_inputTheme inputTheme = new TLRPC.TL_inputTheme();
                    inputTheme.access_hash = themeInfo.info.access_hash;
                    inputTheme.id = themeInfo.info.id;
                    req.theme = inputTheme;
                    ConnectionsManager.getInstance(themeInfo.account).sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.actionbar.-$$Lambda$Theme$S1CmbVmr2n-Ez-MPwBXza0YmPBo
                        @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                        public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.actionbar.-$$Lambda$Theme$AzByj4SxYHnhpEbpG6Sxi8-H_do
                                @Override // java.lang.Runnable
                                public final void run() {
                                    Theme.lambda$null$2(tLObject, themeInfo);
                                }
                            });
                        }
                    });
                }
                a++;
            }
        }
    }

    static /* synthetic */ void lambda$null$2(TLObject response, ThemeInfo themeInfo) {
        loadingCurrentTheme--;
        boolean changed = false;
        if (response instanceof TLRPC.TL_theme) {
            TLRPC.TL_theme theme = (TLRPC.TL_theme) response;
            if (theme.document != null) {
                themeInfo.info = theme;
                themeInfo.loadThemeDocument();
                changed = true;
            }
        }
        if (loadingCurrentTheme == 0) {
            lastLoadingCurrentThemeTime = (int) (System.currentTimeMillis() / 1000);
            saveOtherThemes(changed);
        }
    }

    public static void loadRemoteThemes(final int currentAccount, boolean force) {
        if (loadingRemoteThemes) {
            return;
        }
        if ((!force && Math.abs((System.currentTimeMillis() / 1000) - ((long) lastLoadingThemesTime)) < 3600) || !UserConfig.getInstance(currentAccount).isClientActivated()) {
            return;
        }
        loadingRemoteThemes = true;
        TLRPC.TL_account_getThemes req = new TLRPC.TL_account_getThemes();
        req.format = "android";
        req.hash = remoteThemesHash;
        ConnectionsManager.getInstance(currentAccount).sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.actionbar.-$$Lambda$Theme$5m3Ho5AYtKhpenCCOevBlQVWAaU
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.actionbar.-$$Lambda$Theme$cNnrPa3KUnETKqp4UB43kLpGCnk
                    @Override // java.lang.Runnable
                    public final void run() {
                        Theme.lambda$null$4(tLObject, i);
                    }
                });
            }
        });
    }

    static /* synthetic */ void lambda$null$4(TLObject response, int currentAccount) {
        loadingRemoteThemes = false;
        if (response instanceof TLRPC.TL_account_themes) {
            TLRPC.TL_account_themes res = (TLRPC.TL_account_themes) response;
            remoteThemesHash = res.hash;
            lastLoadingThemesTime = (int) (System.currentTimeMillis() / 1000);
            ArrayList<ThemeInfo> oldServerThemes = new ArrayList<>();
            int N = otherThemes.size();
            for (int a = 0; a < N; a++) {
                ThemeInfo info = otherThemes.get(a);
                if (info.info != null && info.account == currentAccount) {
                    oldServerThemes.add(info);
                }
            }
            int a2 = 0;
            int N2 = res.themes.size();
            for (int a3 = 0; a3 < N2; a3++) {
                TLRPC.Theme t = res.themes.get(a3);
                if (t instanceof TLRPC.TL_theme) {
                    TLRPC.TL_theme theme = (TLRPC.TL_theme) t;
                    String key = "remote" + theme.id;
                    ThemeInfo info2 = themesDict.get(key);
                    if (info2 == null) {
                        info2 = new ThemeInfo();
                        info2.account = currentAccount;
                        info2.pathToFile = new File(ApplicationLoader.getFilesDirFixed(), key + ".attheme").getAbsolutePath();
                        themes.add(info2);
                        otherThemes.add(info2);
                        a2 = 1;
                    } else {
                        oldServerThemes.remove(info2);
                    }
                    info2.name = theme.title;
                    info2.info = theme;
                    themesDict.put(info2.getKey(), info2);
                }
            }
            int N3 = oldServerThemes.size();
            for (int a4 = 0; a4 < N3; a4++) {
                ThemeInfo info3 = oldServerThemes.get(a4);
                info3.removeObservers();
                otherThemes.remove(info3);
                themesDict.remove(info3.name);
                themes.remove(info3);
                File file = new File(info3.pathToFile);
                file.delete();
                boolean isNightTheme = false;
                if (currentDayTheme == info3) {
                    currentDayTheme = defaultTheme;
                } else if (currentNightTheme == info3) {
                    currentNightTheme = themesDict.get("Dark Blue");
                    isNightTheme = true;
                }
                if (currentTheme == info3) {
                    applyTheme(isNightTheme ? currentNightTheme : currentDayTheme, true, false, isNightTheme);
                }
            }
            saveOtherThemes(true);
            sortThemes();
            if (a2 != 0) {
                NotificationCenter.getGlobalInstance().postNotificationName(NotificationCenter.themeListUpdated, new Object[0]);
            }
        }
    }

    public static void setThemeFileReference(TLRPC.TL_theme info) {
        int N = themes.size();
        for (int a = 0; a < N; a++) {
            ThemeInfo themeInfo = themes.get(a);
            if (themeInfo.info != null && themeInfo.info.id == info.id) {
                if (themeInfo.info.document != null && info.document != null) {
                    themeInfo.info.document.file_reference = info.document.file_reference;
                    saveOtherThemes(true);
                    return;
                }
                return;
            }
        }
    }

    public static boolean isThemeInstalled(ThemeInfo themeInfo) {
        return (themeInfo == null || themesDict.get(themeInfo.getKey()) == null) ? false : true;
    }

    public static void setThemeUploadInfo(ThemeInfo theme, TLRPC.TL_theme info, boolean update) throws IOException {
        if (info == null) {
            return;
        }
        String key = "remote" + info.id;
        if (theme != null) {
            themesDict.remove(theme.getKey());
        } else {
            theme = themesDict.get(key);
        }
        if (theme == null) {
            return;
        }
        theme.info = info;
        theme.name = info.title;
        File oldPath = new File(theme.pathToFile);
        File newPath = new File(ApplicationLoader.getFilesDirFixed(), key + ".attheme");
        if (!oldPath.equals(newPath)) {
            try {
                AndroidUtilities.copyFile(oldPath, newPath);
                theme.pathToFile = newPath.getAbsolutePath();
            } catch (Exception e) {
                FileLog.e(e);
            }
        }
        if (update) {
            theme.loadThemeDocument();
        } else {
            theme.previewParsed = false;
        }
        themesDict.put(theme.getKey(), theme);
        saveOtherThemes(true);
    }

    public static File getAssetFile(String assetName) {
        long size;
        File file = new File(ApplicationLoader.getFilesDirFixed(), assetName);
        try {
            InputStream stream = ApplicationLoader.applicationContext.getAssets().open(assetName);
            size = stream.available();
            stream.close();
        } catch (Exception e) {
            size = 0;
            FileLog.e(e);
        }
        if (!file.exists() || (size != 0 && file.length() != size)) {
            try {
                InputStream in = ApplicationLoader.applicationContext.getAssets().open(assetName);
                try {
                    AndroidUtilities.copyFile(in, file);
                    if (in != null) {
                        in.close();
                    }
                } finally {
                }
            } catch (Exception e2) {
                FileLog.e(e2);
            }
        }
        return file;
    }

    private static int getPreviewColor(HashMap<String, Integer> colors, String key) {
        Integer color = colors.get(key);
        if (color == null) {
            color = defaultColors.get(key);
        }
        return color.intValue();
    }

    /* JADX WARN: Removed duplicated region for block: B:126:0x0355 A[Catch: all -> 0x0517, TryCatch #16 {all -> 0x0517, blocks: (B:3:0x0004, B:6:0x010d, B:8:0x0135, B:10:0x014b, B:126:0x0355, B:128:0x036a, B:129:0x0376, B:131:0x0394, B:133:0x03bd, B:136:0x03dc, B:139:0x0406, B:142:0x042a, B:144:0x0438, B:146:0x0460, B:148:0x0485, B:151:0x04aa, B:152:0x04d4, B:157:0x0513, B:7:0x0119, B:14:0x0170, B:86:0x02f3, B:90:0x02fa, B:106:0x032f, B:110:0x0336, B:116:0x033f, B:123:0x034c, B:120:0x0346, B:16:0x0176, B:154:0x04fe, B:104:0x032a), top: B:195:0x0004, inners: #5, #8, #12, #17, #18 }] */
    /* JADX WARN: Removed duplicated region for block: B:130:0x0391  */
    /* JADX WARN: Removed duplicated region for block: B:133:0x03bd A[Catch: all -> 0x0517, TryCatch #16 {all -> 0x0517, blocks: (B:3:0x0004, B:6:0x010d, B:8:0x0135, B:10:0x014b, B:126:0x0355, B:128:0x036a, B:129:0x0376, B:131:0x0394, B:133:0x03bd, B:136:0x03dc, B:139:0x0406, B:142:0x042a, B:144:0x0438, B:146:0x0460, B:148:0x0485, B:151:0x04aa, B:152:0x04d4, B:157:0x0513, B:7:0x0119, B:14:0x0170, B:86:0x02f3, B:90:0x02fa, B:106:0x032f, B:110:0x0336, B:116:0x033f, B:123:0x034c, B:120:0x0346, B:16:0x0176, B:154:0x04fe, B:104:0x032a), top: B:195:0x0004, inners: #5, #8, #12, #17, #18 }] */
    /* JADX WARN: Removed duplicated region for block: B:136:0x03dc A[Catch: all -> 0x0517, TryCatch #16 {all -> 0x0517, blocks: (B:3:0x0004, B:6:0x010d, B:8:0x0135, B:10:0x014b, B:126:0x0355, B:128:0x036a, B:129:0x0376, B:131:0x0394, B:133:0x03bd, B:136:0x03dc, B:139:0x0406, B:142:0x042a, B:144:0x0438, B:146:0x0460, B:148:0x0485, B:151:0x04aa, B:152:0x04d4, B:157:0x0513, B:7:0x0119, B:14:0x0170, B:86:0x02f3, B:90:0x02fa, B:106:0x032f, B:110:0x0336, B:116:0x033f, B:123:0x034c, B:120:0x0346, B:16:0x0176, B:154:0x04fe, B:104:0x032a), top: B:195:0x0004, inners: #5, #8, #12, #17, #18 }] */
    /* JADX WARN: Removed duplicated region for block: B:139:0x0406 A[Catch: all -> 0x0517, TryCatch #16 {all -> 0x0517, blocks: (B:3:0x0004, B:6:0x010d, B:8:0x0135, B:10:0x014b, B:126:0x0355, B:128:0x036a, B:129:0x0376, B:131:0x0394, B:133:0x03bd, B:136:0x03dc, B:139:0x0406, B:142:0x042a, B:144:0x0438, B:146:0x0460, B:148:0x0485, B:151:0x04aa, B:152:0x04d4, B:157:0x0513, B:7:0x0119, B:14:0x0170, B:86:0x02f3, B:90:0x02fa, B:106:0x032f, B:110:0x0336, B:116:0x033f, B:123:0x034c, B:120:0x0346, B:16:0x0176, B:154:0x04fe, B:104:0x032a), top: B:195:0x0004, inners: #5, #8, #12, #17, #18 }] */
    /* JADX WARN: Removed duplicated region for block: B:142:0x042a A[Catch: all -> 0x0517, TryCatch #16 {all -> 0x0517, blocks: (B:3:0x0004, B:6:0x010d, B:8:0x0135, B:10:0x014b, B:126:0x0355, B:128:0x036a, B:129:0x0376, B:131:0x0394, B:133:0x03bd, B:136:0x03dc, B:139:0x0406, B:142:0x042a, B:144:0x0438, B:146:0x0460, B:148:0x0485, B:151:0x04aa, B:152:0x04d4, B:157:0x0513, B:7:0x0119, B:14:0x0170, B:86:0x02f3, B:90:0x02fa, B:106:0x032f, B:110:0x0336, B:116:0x033f, B:123:0x034c, B:120:0x0346, B:16:0x0176, B:154:0x04fe, B:104:0x032a), top: B:195:0x0004, inners: #5, #8, #12, #17, #18 }] */
    /* JADX WARN: Removed duplicated region for block: B:144:0x0438 A[Catch: all -> 0x0517, TryCatch #16 {all -> 0x0517, blocks: (B:3:0x0004, B:6:0x010d, B:8:0x0135, B:10:0x014b, B:126:0x0355, B:128:0x036a, B:129:0x0376, B:131:0x0394, B:133:0x03bd, B:136:0x03dc, B:139:0x0406, B:142:0x042a, B:144:0x0438, B:146:0x0460, B:148:0x0485, B:151:0x04aa, B:152:0x04d4, B:157:0x0513, B:7:0x0119, B:14:0x0170, B:86:0x02f3, B:90:0x02fa, B:106:0x032f, B:110:0x0336, B:116:0x033f, B:123:0x034c, B:120:0x0346, B:16:0x0176, B:154:0x04fe, B:104:0x032a), top: B:195:0x0004, inners: #5, #8, #12, #17, #18 }] */
    /* JADX WARN: Removed duplicated region for block: B:145:0x045e  */
    /* JADX WARN: Removed duplicated region for block: B:148:0x0485 A[Catch: all -> 0x0517, TryCatch #16 {all -> 0x0517, blocks: (B:3:0x0004, B:6:0x010d, B:8:0x0135, B:10:0x014b, B:126:0x0355, B:128:0x036a, B:129:0x0376, B:131:0x0394, B:133:0x03bd, B:136:0x03dc, B:139:0x0406, B:142:0x042a, B:144:0x0438, B:146:0x0460, B:148:0x0485, B:151:0x04aa, B:152:0x04d4, B:157:0x0513, B:7:0x0119, B:14:0x0170, B:86:0x02f3, B:90:0x02fa, B:106:0x032f, B:110:0x0336, B:116:0x033f, B:123:0x034c, B:120:0x0346, B:16:0x0176, B:154:0x04fe, B:104:0x032a), top: B:195:0x0004, inners: #5, #8, #12, #17, #18 }] */
    /* JADX WARN: Removed duplicated region for block: B:151:0x04aa A[Catch: all -> 0x0517, TryCatch #16 {all -> 0x0517, blocks: (B:3:0x0004, B:6:0x010d, B:8:0x0135, B:10:0x014b, B:126:0x0355, B:128:0x036a, B:129:0x0376, B:131:0x0394, B:133:0x03bd, B:136:0x03dc, B:139:0x0406, B:142:0x042a, B:144:0x0438, B:146:0x0460, B:148:0x0485, B:151:0x04aa, B:152:0x04d4, B:157:0x0513, B:7:0x0119, B:14:0x0170, B:86:0x02f3, B:90:0x02fa, B:106:0x032f, B:110:0x0336, B:116:0x033f, B:123:0x034c, B:120:0x0346, B:16:0x0176, B:154:0x04fe, B:104:0x032a), top: B:195:0x0004, inners: #5, #8, #12, #17, #18 }] */
    /* JADX WARN: Removed duplicated region for block: B:173:0x02f3 A[EXC_TOP_SPLITTER, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:179:0x032f A[EXC_TOP_SPLITTER, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:84:0x02e9  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static java.lang.String createThemePreviewImage(im.uwrkaxlmjj.ui.actionbar.Theme.ThemeInfo r41) {
        /*
            Method dump skipped, instruction units count: 1309
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.ui.actionbar.Theme.createThemePreviewImage(im.uwrkaxlmjj.ui.actionbar.Theme$ThemeInfo):java.lang.String");
    }

    private static HashMap<String, Integer> getThemeFileValues(File file, String assetName, String[] wallpaperLink) {
        byte[] bytes;
        int currentPosition;
        File file2;
        boolean finished;
        int wallpaperFileOffset;
        byte[] bytes2;
        byte[] bytes3;
        String param;
        int value;
        String[] strArr = wallpaperLink;
        FileInputStream stream = null;
        HashMap<String, Integer> stringMap = new HashMap<>();
        try {
            try {
                bytes = new byte[1024];
                currentPosition = 0;
                if (assetName == null) {
                    file2 = file;
                } else {
                    file2 = getAssetFile(assetName);
                }
                try {
                    stream = new FileInputStream(file2);
                    finished = false;
                    wallpaperFileOffset = -1;
                } catch (Throwable th) {
                    e = th;
                    try {
                        FileLog.e(e);
                        if (stream != null) {
                            stream.close();
                        }
                        return stringMap;
                    } finally {
                    }
                }
            } catch (Throwable th2) {
                e = th2;
            }
        } catch (Exception e) {
            FileLog.e(e);
        }
        while (true) {
            int read = stream.read(bytes);
            if (read == -1) {
                break;
            }
            int previousPosition = currentPosition;
            int a = 0;
            int start = 0;
            int currentPosition2 = currentPosition;
            while (true) {
                if (a >= read) {
                    bytes2 = bytes;
                    break;
                }
                if (bytes[a] != 10) {
                    bytes3 = bytes;
                } else {
                    int len = (a - start) + 1;
                    String line = new String(bytes, start, len - 1);
                    if (line.startsWith("WLS=")) {
                        if (strArr == null || strArr.length <= 0) {
                            bytes3 = bytes;
                        } else {
                            strArr[0] = line.substring(4);
                            bytes3 = bytes;
                        }
                    } else {
                        if (line.startsWith("WPS")) {
                            int wallpaperFileOffset2 = currentPosition2 + len;
                            finished = true;
                            wallpaperFileOffset = wallpaperFileOffset2;
                            bytes2 = bytes;
                            break;
                        }
                        int idx = line.indexOf(61);
                        if (idx != -1) {
                            String key = line.substring(0, idx);
                            String param2 = line.substring(idx + 1);
                            if (param2.length() <= 0) {
                                param = param2;
                                bytes3 = bytes;
                            } else {
                                param = param2;
                                bytes3 = bytes;
                                if (param.charAt(0) == '#') {
                                    try {
                                        value = Color.parseColor(param);
                                    } catch (Exception e2) {
                                        value = Utilities.parseInt(param).intValue();
                                    }
                                }
                                stringMap.put(key, Integer.valueOf(value));
                            }
                            value = Utilities.parseInt(param).intValue();
                            stringMap.put(key, Integer.valueOf(value));
                        } else {
                            bytes3 = bytes;
                        }
                        return stringMap;
                    }
                    start += len;
                    currentPosition2 += len;
                }
                a++;
                strArr = wallpaperLink;
                bytes = bytes3;
            }
            if (previousPosition == currentPosition2) {
                break;
            }
            stream.getChannel().position(currentPosition2);
            if (finished) {
                break;
            }
            strArr = wallpaperLink;
            currentPosition = currentPosition2;
            bytes = bytes2;
        }
        stringMap.put("wallpaperFileOffset", Integer.valueOf(wallpaperFileOffset));
        stream.close();
        return stringMap;
    }

    public static void createCommonResources(Context context) {
        if (dividerPaint == null) {
            Paint paint = new Paint();
            dividerPaint = paint;
            paint.setStrokeWidth(1.0f);
            avatar_backgroundPaint = new Paint(1);
            Paint paint2 = new Paint(1);
            checkboxSquare_checkPaint = paint2;
            paint2.setStyle(Paint.Style.STROKE);
            checkboxSquare_checkPaint.setStrokeWidth(AndroidUtilities.dp(2.0f));
            Paint paint3 = new Paint(1);
            checkboxSquare_eraserPaint = paint3;
            paint3.setColor(0);
            checkboxSquare_eraserPaint.setXfermode(new PorterDuffXfermode(PorterDuff.Mode.CLEAR));
            checkboxSquare_backgroundPaint = new Paint(1);
            linkSelectionPaint = new Paint();
            Resources resources = context.getResources();
            avatar_savedDrawable = resources.getDrawable(R.drawable.chats_saved);
            avatar_ghostDrawable = resources.getDrawable(R.drawable.ghost);
            RLottieDrawable rLottieDrawable = dialogs_archiveAvatarDrawable;
            if (rLottieDrawable != null) {
                rLottieDrawable.setCallback(null);
                dialogs_archiveAvatarDrawable.recycle();
            }
            RLottieDrawable rLottieDrawable2 = dialogs_archiveDrawable;
            if (rLottieDrawable2 != null) {
                rLottieDrawable2.recycle();
            }
            RLottieDrawable rLottieDrawable3 = dialogs_unarchiveDrawable;
            if (rLottieDrawable3 != null) {
                rLottieDrawable3.recycle();
            }
            RLottieDrawable rLottieDrawable4 = dialogs_pinArchiveDrawable;
            if (rLottieDrawable4 != null) {
                rLottieDrawable4.recycle();
            }
            RLottieDrawable rLottieDrawable5 = dialogs_unpinArchiveDrawable;
            if (rLottieDrawable5 != null) {
                rLottieDrawable5.recycle();
            }
            dialogs_archiveAvatarDrawable = new RLottieDrawable(R.raw.chats_archiveavatar, "chats_archiveavatar", AndroidUtilities.dp(36.0f), AndroidUtilities.dp(36.0f), false);
            dialogs_archiveDrawable = new RLottieDrawable(R.raw.chats_archive, "chats_archive", AndroidUtilities.dp(36.0f), AndroidUtilities.dp(36.0f));
            dialogs_unarchiveDrawable = new RLottieDrawable(R.raw.chats_unarchive, "chats_unarchive", AndroidUtilities.dp(AndroidUtilities.dp(36.0f)), AndroidUtilities.dp(36.0f));
            dialogs_pinArchiveDrawable = new RLottieDrawable(R.raw.chats_hide, "chats_hide", AndroidUtilities.dp(36.0f), AndroidUtilities.dp(36.0f));
            dialogs_unpinArchiveDrawable = new RLottieDrawable(R.raw.chats_unhide, "chats_unhide", AndroidUtilities.dp(36.0f), AndroidUtilities.dp(36.0f));
            applyCommonTheme();
        }
    }

    public static void applyCommonTheme() {
        Paint paint = dividerPaint;
        if (paint == null) {
            return;
        }
        paint.setColor(getColor(key_divider));
        linkSelectionPaint.setColor(getColor(key_windowBackgroundWhiteLinkSelection));
        setDrawableColorByKey(avatar_savedDrawable, key_avatar_text);
        dialogs_archiveAvatarDrawable.setLayerColor("Arrow1.**", getColor(key_avatar_backgroundArchived));
        dialogs_archiveAvatarDrawable.setLayerColor("Arrow2.**", getColor(key_avatar_backgroundArchived));
        dialogs_archiveAvatarDrawable.setLayerColor("Box2.**", getColor(key_avatar_text));
        dialogs_archiveAvatarDrawable.setLayerColor("Box1.**", getColor(key_avatar_text));
        dialogs_archiveAvatarDrawableRecolored = false;
        dialogs_archiveAvatarDrawable.setAllowDecodeSingleFrame(true);
        dialogs_pinArchiveDrawable.setLayerColor("Arrow.**", getColor(key_chats_archiveIcon));
        dialogs_pinArchiveDrawable.setLayerColor("Line.**", getColor(key_chats_archiveIcon));
        dialogs_unpinArchiveDrawable.setLayerColor("Arrow.**", getColor(key_chats_archiveIcon));
        dialogs_unpinArchiveDrawable.setLayerColor("Line.**", getColor(key_chats_archiveIcon));
        dialogs_archiveDrawable.setLayerColor("Arrow.**", getColor(key_chats_archiveBackground));
        dialogs_archiveDrawable.setLayerColor("Box2.**", getColor(key_chats_archiveIcon));
        dialogs_archiveDrawable.setLayerColor("Box1.**", getColor(key_chats_archiveIcon));
        dialogs_archiveDrawableRecolored = false;
        dialogs_unarchiveDrawable.setLayerColor("Arrow1.**", getColor(key_chats_archiveIcon));
        dialogs_unarchiveDrawable.setLayerColor("Arrow2.**", getColor(key_chats_archivePinBackground));
        dialogs_unarchiveDrawable.setLayerColor("Box2.**", getColor(key_chats_archiveIcon));
        dialogs_unarchiveDrawable.setLayerColor("Box1.**", getColor(key_chats_archiveIcon));
    }

    public static void createDialogsResources(Context context) {
        createCommonResources(context);
        if (dialogs_namePaint == null) {
            Resources resources = context.getResources();
            dialogs_namePaint = new TextPaint(1);
            dialogs_nameEncryptedPaint = new TextPaint(1);
            dialogs_searchNamePaint = new TextPaint(1);
            dialogs_searchNameEncryptedPaint = new TextPaint(1);
            dialogs_messagePaint = new TextPaint(1);
            dialogs_messageNamePaint = new TextPaint(1);
            dialogs_messagePrintingPaint = new TextPaint(1);
            dialogs_timePaint = new TextPaint(1);
            TextPaint textPaint = new TextPaint(1);
            dialogs_countTextPaint = textPaint;
            textPaint.setTypeface(AndroidUtilities.getTypeface("fonts/rmedium.ttf"));
            TextPaint textPaint2 = new TextPaint(1);
            dialogs_archiveTextPaint = textPaint2;
            textPaint2.setTypeface(AndroidUtilities.getTypeface("fonts/rmedium.ttf"));
            dialogs_onlinePaint = new TextPaint(1);
            dialogs_offlinePaint = new TextPaint(1);
            dialogs_tabletSeletedPaint = new Paint();
            dialogs_pinnedPaint = new Paint(1);
            dialogs_onlineCirclePaint = new Paint(1);
            dialogs_countPaint = new Paint(1);
            dialogs_countGrayPaint = new Paint(1);
            dialogs_errorPaint = new Paint(1);
            dialogs_menuPaint = new Paint(1);
            dialogs_lockDrawable = resources.getDrawable(R.drawable.list_secret);
            dialogs_checkDrawable = resources.getDrawable(R.drawable.list_check).mutate();
            dialogs_checkReadDrawable = resources.getDrawable(R.drawable.list_check).mutate();
            dialogs_halfCheckDrawable = resources.getDrawable(R.drawable.list_halfcheck);
            dialogs_checkReadDrawable1 = resources.getDrawable(R.drawable.list_check_fmt).mutate();
            dialogs_halfCheckDrawable1 = resources.getDrawable(R.drawable.list_halfcheck_fmt);
            dialogs_clockDrawable = resources.getDrawable(R.drawable.msg_clock).mutate();
            dialogs_errorDrawable = resources.getDrawable(R.drawable.list_warning_sign);
            dialogs_reorderDrawable = resources.getDrawable(R.drawable.list_reorder);
            dialogs_groupDrawable = resources.getDrawable(R.drawable.list_group);
            dialogs_broadcastDrawable = resources.getDrawable(R.drawable.list_broadcast);
            dialogs_muteDrawable = resources.getDrawable(R.drawable.list_mute).mutate();
            dialogs_verifiedDrawable = resources.getDrawable(R.drawable.verified_area);
            dialogs_scamDrawable = new ScamDrawable(11);
            dialogs_verifiedCheckDrawable = resources.getDrawable(R.drawable.verified_check);
            dialogs_mentionDrawable = resources.getDrawable(R.drawable.mentionchatslist);
            dialogs_botDrawable = resources.getDrawable(R.drawable.list_bot);
            dialogs_pinnedDrawable = resources.getDrawable(R.drawable.list_pin);
            moveUpDrawable = resources.getDrawable(R.drawable.preview_open);
            dialogs_pinDrawable = resources.getDrawable(R.drawable.chats_pin);
            dialogs_deleteDrawable = resources.getDrawable(R.drawable.chats_delete);
            applyDialogsTheme();
        }
        dialogs_messageNamePaint.setTextSize(AndroidUtilities.sp2px(12.0f));
        dialogs_timePaint.setTextSize(AndroidUtilities.dp(13.0f));
        dialogs_countTextPaint.setTextSize(AndroidUtilities.sp2px(11.0f));
        dialogs_archiveTextPaint.setTextSize(AndroidUtilities.dp(13.0f));
        dialogs_onlinePaint.setTextSize(AndroidUtilities.dp(13.0f));
        dialogs_offlinePaint.setTextSize(AndroidUtilities.sp2px(13.0f));
        dialogs_searchNamePaint.setTextSize(AndroidUtilities.dp(16.0f));
        dialogs_searchNameEncryptedPaint.setTextSize(AndroidUtilities.dp(16.0f));
    }

    public static void applyDialogsTheme() {
        TextPaint textPaint = dialogs_namePaint;
        if (textPaint == null) {
            return;
        }
        textPaint.setColor(getColor(key_chats_name));
        dialogs_nameEncryptedPaint.setColor(getColor(key_chats_secretName));
        dialogs_searchNamePaint.setColor(getColor(key_chats_name));
        dialogs_searchNameEncryptedPaint.setColor(getColor(key_chats_secretName));
        TextPaint textPaint2 = dialogs_messagePaint;
        int color = getColor(key_chats_message);
        textPaint2.linkColor = color;
        textPaint2.setColor(color);
        TextPaint textPaint3 = dialogs_messageNamePaint;
        int color2 = getColor(key_chats_nameMessage_threeLines);
        textPaint3.linkColor = color2;
        textPaint3.setColor(color2);
        dialogs_tabletSeletedPaint.setColor(getColor(key_chats_tabletSelectedOverlay));
        dialogs_pinnedPaint.setColor(getColor(key_chats_pinnedOverlay));
        dialogs_timePaint.setColor(getColor(key_chats_date));
        dialogs_countTextPaint.setColor(getColor(key_chats_unreadCounterText));
        dialogs_archiveTextPaint.setColor(getColor(key_chats_archiveText));
        dialogs_messagePrintingPaint.setColor(getColor(key_chats_actionMessage));
        dialogs_countPaint.setColor(getColor(key_chats_unreadCounter));
        dialogs_countGrayPaint.setColor(getColor(key_chats_unreadCounterMuted));
        dialogs_errorPaint.setColor(getColor(key_chats_sentError));
        dialogs_onlinePaint.setColor(getColor(key_windowBackgroundWhiteBlueText3));
        dialogs_offlinePaint.setColor(getColor(key_windowBackgroundWhiteGrayText3));
        dialogs_menuPaint.setColor(getColor(key_windowBackgroundWhite));
        setDrawableColorByKey(dialogs_checkDrawable, key_chats_sentCheck);
        setDrawableColorByKey(dialogs_checkReadDrawable, key_chats_sentReadCheck);
        setDrawableColorByKey(dialogs_halfCheckDrawable, key_chats_sentReadCheck);
        setDrawableColorByKey(dialogs_clockDrawable, key_chats_sentClock);
        setDrawableColorByKey(dialogs_errorDrawable, key_chats_sentErrorIcon);
        setDrawableColorByKey(dialogs_botDrawable, key_chats_nameIcon);
        setDrawableColorByKey(dialogs_pinnedDrawable, key_chats_pinnedIcon);
        setDrawableColorByKey(dialogs_reorderDrawable, key_chats_pinnedIcon);
        setDrawableColorByKey(dialogs_muteDrawable, key_chats_muteIcon);
        setDrawableColorByKey(dialogs_mentionDrawable, key_chats_mentionIcon);
        setDrawableColorByKey(dialogs_verifiedDrawable, key_chats_verifiedBackground);
        setDrawableColorByKey(dialogs_verifiedCheckDrawable, key_chats_verifiedCheck);
        setDrawableColorByKey(dialogs_holidayDrawable, key_actionBarDefaultTitle);
        setDrawableColorByKey(dialogs_scamDrawable, key_chats_draft);
        setDrawableColorByKey(dialogs_deleteDrawable, key_chats_draft);
        setDrawableColorByKey(dialogs_pinDrawable, key_chats_draft);
    }

    public static void destroyResources() {
        int a = 0;
        while (true) {
            Drawable[] drawableArr = chat_attachButtonDrawables;
            if (a < drawableArr.length) {
                if (drawableArr[a] != null) {
                    drawableArr[a].setCallback(null);
                }
                a++;
            } else {
                return;
            }
        }
    }

    public static void reloadAllResources(Context context) {
        destroyResources();
        if (chat_msgInDrawable != null) {
            chat_msgInDrawable = null;
            currentColor = 0;
            currentSelectedColor = 0;
            createChatResources(context, false);
        }
        if (dialogs_namePaint != null) {
            dialogs_namePaint = null;
            createDialogsResources(context);
        }
        if (profile_verifiedDrawable != null) {
            profile_verifiedDrawable = null;
            createProfileResources(context);
        }
    }

    public static void createChatResources(Context context, boolean fontsOnly) {
        Paint paint;
        synchronized (sync) {
            if (chat_msgTextPaint == null) {
                chat_msgTextPaint = new TextPaint(1);
                chat_captionTextPaint = new TextPaint(1);
                chat_msgGameTextPaint = new TextPaint(1);
                chat_msgTextPaintOneEmoji = new TextPaint(1);
                chat_msgTextPaintTwoEmoji = new TextPaint(1);
                chat_msgTextPaintThreeEmoji = new TextPaint(1);
                TextPaint textPaint = new TextPaint(1);
                chat_msgBotButtonPaint = textPaint;
                textPaint.setTypeface(AndroidUtilities.getTypeface("fonts/rmedium.ttf"));
            }
        }
        if (!fontsOnly && chat_msgInDrawable == null) {
            chat_infoPaint = new TextPaint(1);
            chat_docNamePaint = new TextPaint(1);
            chat_docBackPaint = new Paint(1);
            chat_deleteProgressPaint = new Paint(1);
            Paint paint2 = new Paint(1);
            chat_botProgressPaint = paint2;
            paint2.setStrokeCap(Paint.Cap.ROUND);
            chat_botProgressPaint.setStyle(Paint.Style.STROKE);
            TextPaint textPaint2 = new TextPaint(1);
            chat_locationTitlePaint = textPaint2;
            textPaint2.setTypeface(AndroidUtilities.getTypeface("fonts/rmedium.ttf"));
            chat_locationAddressPaint = new TextPaint(1);
            chat_urlPaint = new Paint();
            chat_textSearchSelectionPaint = new Paint();
            Paint paint3 = new Paint(1);
            chat_radialProgressPaint = paint3;
            paint3.setStrokeCap(Paint.Cap.ROUND);
            chat_radialProgressPaint.setStyle(Paint.Style.STROKE);
            chat_radialProgressPaint.setColor(-1610612737);
            Paint paint4 = new Paint(1);
            chat_radialProgress2Paint = paint4;
            paint4.setStrokeCap(Paint.Cap.ROUND);
            chat_radialProgress2Paint.setStyle(Paint.Style.STROKE);
            chat_audioTimePaint = new TextPaint(1);
            TextPaint textPaint3 = new TextPaint(1);
            chat_livePaint = textPaint3;
            textPaint3.setTypeface(AndroidUtilities.getTypeface("fonts/rmedium.ttf"));
            chat_audioTitlePaint = new TextPaint(1);
            chat_audioPerformerPaint = new TextPaint(1);
            TextPaint textPaint4 = new TextPaint(1);
            chat_botButtonPaint = textPaint4;
            textPaint4.setTypeface(AndroidUtilities.getTypeface("fonts/rmedium.ttf"));
            TextPaint textPaint5 = new TextPaint(1);
            chat_contactNamePaint = textPaint5;
            textPaint5.setTypeface(AndroidUtilities.getTypeface("fonts/rmedium.ttf"));
            chat_contactPhonePaint = new TextPaint(1);
            chat_durationPaint = new TextPaint(1);
            TextPaint textPaint6 = new TextPaint(1);
            chat_gamePaint = textPaint6;
            textPaint6.setTypeface(AndroidUtilities.getTypeface("fonts/rmedium.ttf"));
            chat_shipmentPaint = new TextPaint(1);
            chat_timePaint = new TextPaint(1);
            chat_adminPaint = new TextPaint(1);
            chat_namePaint = new TextPaint(1);
            chat_forwardNamePaint = new TextPaint(1);
            TextPaint textPaint7 = new TextPaint(1);
            chat_replyNamePaint = textPaint7;
            textPaint7.setTypeface(AndroidUtilities.getTypeface("fonts/rmedium.ttf"));
            chat_replyTextPaint = new TextPaint(1);
            chat_redpkgTextPaint = new TextPaint(1);
            chat_redpkgBackgoundPaint = new TextPaint(1);
            TextPaint textPaint8 = new TextPaint(1);
            chat_instantViewPaint = textPaint8;
            textPaint8.setTypeface(AndroidUtilities.getTypeface("fonts/rmedium.ttf"));
            Paint paint5 = new Paint(1);
            chat_instantViewRectPaint = paint5;
            paint5.setStyle(Paint.Style.STROKE);
            chat_replyLinePaint = new Paint(1);
            Paint paint6 = new Paint(1);
            chat_replyBackgroundPaint = paint6;
            paint6.setColor(getColor(key_chat_replyBackground));
            chat_msgErrorPaint = new Paint(1);
            chat_statusPaint = new Paint(1);
            Paint paint7 = new Paint(1);
            chat_statusRecordPaint = paint7;
            paint7.setStyle(Paint.Style.STROKE);
            chat_statusRecordPaint.setStrokeCap(Paint.Cap.ROUND);
            chat_actionTextPaint = new TextPaint(1);
            chat_actionBackgroundPaint = new Paint(1);
            chat_actionBackgroundPaint2 = new Paint(1);
            chat_timeBackgroundPaint = new Paint(1);
            TextPaint textPaint9 = new TextPaint(1);
            chat_contextResult_titleTextPaint = textPaint9;
            textPaint9.setTypeface(AndroidUtilities.getTypeface("fonts/rmedium.ttf"));
            chat_contextResult_descriptionTextPaint = new TextPaint(1);
            chat_composeBackgroundPaint = new Paint();
            chat_translationPaint = new TextPaint(1);
            Resources resources = context.getResources();
            chat_msgInDrawable = resources.getDrawable(R.id.msg_left).mutate();
            chat_msgInSelectedDrawable = resources.getDrawable(R.id.msg_left).mutate();
            chat_msgOutDrawable = resources.getDrawable(R.id.msg_right).mutate();
            chat_msgOutSelectedDrawable = resources.getDrawable(R.id.msg_right).mutate();
            chat_msgRedpkgCloudDrawable = resources.getDrawable(R.id.redpkg_cloud_icon).mutate();
            chat_msgRedpkgInDrawable = resources.getDrawable(R.id.msg_left).mutate();
            chat_msgRedpkgInSelectedDrawable = resources.getDrawable(R.id.msg_left).mutate();
            chat_msgRedpkgOutDrawable = resources.getDrawable(R.id.msg_right).mutate();
            chat_msgRedpkgOutSelectedDrawable = resources.getDrawable(R.id.msg_right).mutate();
            chat_msgRedpkgInMediaDrawable = resources.getDrawable(R.id.msg_media).mutate();
            chat_msgRedpkgInMediaSelectedDrawable = resources.getDrawable(R.id.msg_media).mutate();
            chat_msgRedpkgOutMediaDrawable = resources.getDrawable(R.id.msg_media).mutate();
            chat_msgRedpkgOutMediaSelectedDrawable = resources.getDrawable(R.id.msg_media).mutate();
            chat_msgNoSoundDrawable = resources.getDrawable(R.drawable.video_muted);
            chat_msgInMediaDrawable = resources.getDrawable(R.id.msg_media).mutate();
            chat_msgInMediaSelectedDrawable = resources.getDrawable(R.id.msg_media).mutate();
            chat_msgOutMediaDrawable = resources.getDrawable(R.id.msg_media).mutate();
            chat_msgOutMediaSelectedDrawable = resources.getDrawable(R.id.msg_media).mutate();
            chat_msgOutCheckGrayDrawable = resources.getDrawable(R.drawable.msg_check).mutate();
            chat_msgOutCheckGraySelectedDrawable = resources.getDrawable(R.drawable.msg_check).mutate();
            chat_msgOutCheckReadGrayDrawable = resources.getDrawable(R.drawable.msg_check).mutate();
            chat_msgOutCheckReadGraySelectedDrawable = resources.getDrawable(R.drawable.msg_check).mutate();
            chat_msgOutHalfGrayCheckDrawable = resources.getDrawable(R.drawable.msg_halfcheck).mutate();
            chat_msgOutHalfGrayCheckSelectedDrawable = resources.getDrawable(R.drawable.msg_halfcheck).mutate();
            chat_msgMediaHalfGrayCheckDrawable = resources.getDrawable(R.drawable.msg_halfcheck).mutate();
            chat_msgStickerHalfGrayCheckDrawable = resources.getDrawable(R.drawable.msg_halfcheck).mutate();
            chat_msgOutCheckDrawable = resources.getDrawable(R.drawable.msg_check).mutate();
            chat_msgOutCheckSelectedDrawable = resources.getDrawable(R.drawable.msg_check).mutate();
            chat_msgOutCheckReadDrawable = resources.getDrawable(R.drawable.msg_check).mutate();
            chat_msgOutCheckReadSelectedDrawable = resources.getDrawable(R.drawable.msg_check).mutate();
            chat_sysNotifyDrawable = resources.getDrawable(R.id.iv_chat_sys_bg).mutate();
            chat_sysNotifyRightDrawable = resources.getDrawable(R.id.iv_chat_sys_right_bg).mutate();
            chat_msgMediaCheckDrawable = resources.getDrawable(R.drawable.msg_check).mutate();
            chat_msgStickerCheckDrawable = resources.getDrawable(R.drawable.msg_check).mutate();
            chat_msgOutHalfCheckDrawable = resources.getDrawable(R.drawable.msg_halfcheck).mutate();
            chat_msgOutHalfCheckSelectedDrawable = resources.getDrawable(R.drawable.msg_halfcheck).mutate();
            chat_msgMediaHalfCheckDrawable = resources.getDrawable(R.drawable.msg_halfcheck).mutate();
            chat_msgStickerHalfCheckDrawable = resources.getDrawable(R.drawable.msg_halfcheck).mutate();
            chat_msgOutGrayClockDrawable = resources.getDrawable(R.drawable.msg_clock).mutate();
            chat_msgOutGraySelectedClockDrawable = resources.getDrawable(R.drawable.msg_clock).mutate();
            chat_msgOutClockDrawable = resources.getDrawable(R.drawable.msg_clock).mutate();
            chat_msgOutSelectedClockDrawable = resources.getDrawable(R.drawable.msg_clock).mutate();
            chat_msgInClockDrawable = resources.getDrawable(R.drawable.msg_clock).mutate();
            chat_msgInSelectedClockDrawable = resources.getDrawable(R.drawable.msg_clock).mutate();
            chat_msgMediaClockDrawable = resources.getDrawable(R.drawable.msg_clock).mutate();
            chat_msgStickerClockDrawable = resources.getDrawable(R.drawable.msg_clock).mutate();
            chat_msgInViewsDrawable = resources.getDrawable(R.drawable.msg_views).mutate();
            chat_msgInViewsSelectedDrawable = resources.getDrawable(R.drawable.msg_views).mutate();
            chat_msgOutViewsDrawable = resources.getDrawable(R.drawable.msg_views).mutate();
            chat_msgOutViewsSelectedDrawable = resources.getDrawable(R.drawable.msg_views).mutate();
            chat_msgMediaViewsDrawable = resources.getDrawable(R.drawable.msg_views).mutate();
            chat_msgStickerViewsDrawable = resources.getDrawable(R.drawable.msg_views).mutate();
            chat_msgInMenuDrawable = resources.getDrawable(R.drawable.msg_actions).mutate();
            chat_msgInMenuSelectedDrawable = resources.getDrawable(R.drawable.msg_actions).mutate();
            chat_msgOutMenuDrawable = resources.getDrawable(R.drawable.msg_actions).mutate();
            chat_msgOutMenuSelectedDrawable = resources.getDrawable(R.drawable.msg_actions).mutate();
            chat_msgMediaMenuDrawable = resources.getDrawable(R.drawable.video_actions);
            chat_msgInInstantDrawable = resources.getDrawable(R.drawable.msg_instant).mutate();
            chat_msgOutInstantDrawable = resources.getDrawable(R.drawable.msg_instant).mutate();
            chat_msgErrorDrawable = resources.getDrawable(R.drawable.msg_warning);
            chat_muteIconDrawable = resources.getDrawable(R.drawable.list_mute).mutate();
            chat_lockIconDrawable = resources.getDrawable(R.drawable.ic_lock_header);
            chat_msgBroadcastDrawable = resources.getDrawable(R.drawable.broadcast3).mutate();
            chat_msgBroadcastMediaDrawable = resources.getDrawable(R.drawable.broadcast3).mutate();
            chat_msgInCallDrawable = resources.getDrawable(R.drawable.ic_call).mutate();
            chat_msgInCallSelectedDrawable = resources.getDrawable(R.drawable.ic_call).mutate();
            chat_msgOutCallDrawable = resources.getDrawable(R.drawable.ic_call).mutate();
            chat_msgOutCallSelectedDrawable = resources.getDrawable(R.drawable.ic_call).mutate();
            chat_msgVideoCallDrawable = resources.getDrawable(R.id.visualcall_video);
            chat_msgVoiceCallDrawable = resources.getDrawable(R.id.visualcall_voice);
            chat_msgOutVideoCallDrawable = resources.getDrawable(R.id.visualcall_video);
            chat_msgOutVoiceCallDrawable = resources.getDrawable(R.id.visualcall_voice);
            chat_msgCallUpGreenDrawable = resources.getDrawable(R.drawable.ic_call_made_green_18dp).mutate();
            chat_msgCallDownRedDrawable = resources.getDrawable(R.drawable.ic_call_received_green_18dp).mutate();
            chat_msgCallDownGreenDrawable = resources.getDrawable(R.drawable.ic_call_received_green_18dp).mutate();
            chat_msgLiveLogoDrawable = resources.getDrawable(R.id.ic_live_msg).mutate();
            calllog_msgCallUpRedDrawable = resources.getDrawable(R.drawable.ic_call_made_green_18dp).mutate();
            calllog_msgCallUpGreenDrawable = resources.getDrawable(R.drawable.ic_call_made_green_18dp).mutate();
            calllog_msgCallDownRedDrawable = resources.getDrawable(R.drawable.ic_call_received_green_18dp).mutate();
            calllog_msgCallDownGreenDrawable = resources.getDrawable(R.drawable.ic_call_received_green_18dp).mutate();
            chat_msgAvatarLiveLocationDrawable = resources.getDrawable(R.drawable.livepin).mutate();
            chat_inlineResultFile = resources.getDrawable(R.drawable.bot_file);
            chat_inlineResultAudio = resources.getDrawable(R.drawable.bot_music);
            chat_inlineResultLocation = resources.getDrawable(R.drawable.bot_location);
            chat_redLocationIcon = resources.getDrawable(R.drawable.map_pin).mutate();
            chat_redpkgUnreceivedIcon = resources.getDrawable(R.id.red_pkg_icon).mutate();
            chat_redpkgReceivedIcon = resources.getDrawable(R.id.red_pkg_recved_icon).mutate();
            chat_redpkgSamllIcon = resources.getDrawable(R.id.ic_red_small).mutate();
            chat_gameInThunderBackground = resources.getDrawable(R.id.img_game_thunder_veins_in).mutate();
            chat_gameOutThunderBackground = resources.getDrawable(R.id.img_game_thunder_veins_out).mutate();
            chat_msgOutAudioFlagIcon = resources.getDrawable(R.id.ic_audio_flag).mutate();
            chat_msgInAudioFlagIcon = resources.getDrawable(R.id.ic_audio_flag).mutate();
            chat_msgAudioBlueFlagIcon = resources.getDrawable(R.id.ic_audio_blue_flag).mutate();
            chat_msgOutTranslateIcon = resources.getDrawable(R.id.ic_msg_out_translate).mutate();
            chat_msgInTranslateIcon = resources.getDrawable(R.id.ic_msg_in_translate).mutate();
            chat_msgTransferNormalIcon = resources.getDrawable(R.id.messages_transer_icon).mutate();
            chat_msgTransferReceiveIcon = resources.getDrawable(R.id.messages_transfer_receive_icon).mutate();
            chat_msgTransferBackIcon = resources.getDrawable(R.id.messages_transfer_back_icon).mutate();
            chat_msgInShadowDrawable = resources.getDrawable(R.id.msg_left_shadow);
            chat_msgOutShadowDrawable = resources.getDrawable(R.id.msg_right_shadow);
            chat_msgInMediaShadowDrawable = resources.getDrawable(R.id.msg_media_shadow);
            chat_msgOutMediaShadowDrawable = resources.getDrawable(R.id.msg_media_shadow);
            chat_botLinkDrawalbe = resources.getDrawable(R.drawable.bot_link);
            chat_botInlineDrawable = resources.getDrawable(R.drawable.bot_lines);
            chat_systemDrawable = resources.getDrawable(R.drawable.system);
            chat_contextResult_shadowUnderSwitchDrawable = resources.getDrawable(R.drawable.header_shadow).mutate();
            chat_attachButtonDrawables[0] = createCircleDrawableWithIcon(AndroidUtilities.dp(50.0f), R.drawable.attach_gallery);
            chat_attachButtonDrawables[1] = createCircleDrawableWithIcon(AndroidUtilities.dp(50.0f), R.drawable.attach_audio);
            chat_attachButtonDrawables[2] = createCircleDrawableWithIcon(AndroidUtilities.dp(50.0f), R.drawable.attach_file);
            chat_attachButtonDrawables[3] = createCircleDrawableWithIcon(AndroidUtilities.dp(50.0f), R.drawable.attach_contact);
            chat_attachButtonDrawables[4] = createCircleDrawableWithIcon(AndroidUtilities.dp(50.0f), R.drawable.attach_location);
            chat_attachButtonDrawables[5] = createCircleDrawableWithIcon(AndroidUtilities.dp(50.0f), R.drawable.attach_polls);
            chat_attachEmptyDrawable = resources.getDrawable(R.drawable.nophotos3);
            chat_cornerOuter[0] = resources.getDrawable(R.drawable.corner_out_tl);
            chat_cornerOuter[1] = resources.getDrawable(R.drawable.corner_out_tr);
            chat_cornerOuter[2] = resources.getDrawable(R.drawable.corner_out_br);
            chat_cornerOuter[3] = resources.getDrawable(R.drawable.corner_out_bl);
            chat_cornerInner[0] = resources.getDrawable(R.drawable.corner_in_tr);
            chat_cornerInner[1] = resources.getDrawable(R.drawable.corner_in_tl);
            chat_cornerInner[2] = resources.getDrawable(R.drawable.corner_in_br);
            chat_cornerInner[3] = resources.getDrawable(R.drawable.corner_in_bl);
            chat_shareDrawable = resources.getDrawable(R.drawable.share_round);
            chat_shareIconDrawable = resources.getDrawable(R.drawable.share_arrow);
            chat_replyIconDrawable = resources.getDrawable(R.drawable.fast_reply);
            chat_goIconDrawable = resources.getDrawable(R.drawable.message_arrow);
            chat_fileMiniStatesDrawable[0][0] = createCircleDrawableWithIcon(AndroidUtilities.dp(22.0f), R.drawable.audio_mini_arrow);
            chat_fileMiniStatesDrawable[0][1] = createCircleDrawableWithIcon(AndroidUtilities.dp(22.0f), R.drawable.audio_mini_arrow);
            chat_fileMiniStatesDrawable[1][0] = createCircleDrawableWithIcon(AndroidUtilities.dp(22.0f), R.drawable.audio_mini_cancel);
            chat_fileMiniStatesDrawable[1][1] = createCircleDrawableWithIcon(AndroidUtilities.dp(22.0f), R.drawable.audio_mini_cancel);
            chat_fileMiniStatesDrawable[2][0] = createCircleDrawableWithIcon(AndroidUtilities.dp(22.0f), R.drawable.audio_mini_arrow);
            chat_fileMiniStatesDrawable[2][1] = createCircleDrawableWithIcon(AndroidUtilities.dp(22.0f), R.drawable.audio_mini_arrow);
            chat_fileMiniStatesDrawable[3][0] = createCircleDrawableWithIcon(AndroidUtilities.dp(22.0f), R.drawable.audio_mini_cancel);
            chat_fileMiniStatesDrawable[3][1] = createCircleDrawableWithIcon(AndroidUtilities.dp(22.0f), R.drawable.audio_mini_cancel);
            chat_fileMiniStatesDrawable[4][0] = createCircleDrawableWithIcon(AndroidUtilities.dp(22.0f), R.drawable.video_mini_arrow);
            chat_fileMiniStatesDrawable[4][1] = createCircleDrawableWithIcon(AndroidUtilities.dp(22.0f), R.drawable.video_mini_arrow);
            chat_fileMiniStatesDrawable[5][0] = createCircleDrawableWithIcon(AndroidUtilities.dp(22.0f), R.drawable.video_mini_cancel);
            chat_fileMiniStatesDrawable[5][1] = createCircleDrawableWithIcon(AndroidUtilities.dp(22.0f), R.drawable.video_mini_cancel);
            chat_fileIcon = resources.getDrawable(R.drawable.msg_round_file_s).mutate();
            chat_fileCompressIcon = resources.getDrawable(R.id.icon_msg_compress).mutate();
            chat_fileDocIcon = resources.getDrawable(R.id.icon_msg_doc).mutate();
            chat_fileXlsIcon = resources.getDrawable(R.id.icon_msg_xls).mutate();
            chat_filePdfIcon = resources.getDrawable(R.id.icon_msg_pdf).mutate();
            chat_fileTxtIcon = resources.getDrawable(R.id.icon_msg_txt).mutate();
            chat_fileApkIcon = resources.getDrawable(R.id.icon_msg_apk).mutate();
            chat_fileIpaIcon = resources.getDrawable(R.id.icon_msg_ipa).mutate();
            chat_fileNoneIcon = resources.getDrawable(R.id.icon_msg_none).mutate();
            chat_flameIcon = resources.getDrawable(R.drawable.burn).mutate();
            chat_gifIcon = resources.getDrawable(R.drawable.msg_round_gif_m).mutate();
            chat_fileStatesDrawable[0][0] = createCircleDrawableWithIcon(AndroidUtilities.dp(44.0f), R.drawable.msg_round_play_m);
            chat_fileStatesDrawable[0][1] = createCircleDrawableWithIcon(AndroidUtilities.dp(44.0f), R.drawable.msg_round_play_m);
            chat_fileStatesDrawable[1][0] = createCircleDrawableWithIcon(AndroidUtilities.dp(44.0f), R.drawable.msg_round_pause_m);
            chat_fileStatesDrawable[1][1] = createCircleDrawableWithIcon(AndroidUtilities.dp(44.0f), R.drawable.msg_round_pause_m);
            chat_fileStatesDrawable[2][0] = createCircleDrawableWithIcon(AndroidUtilities.dp(44.0f), R.drawable.msg_round_load_m);
            chat_fileStatesDrawable[2][1] = createCircleDrawableWithIcon(AndroidUtilities.dp(44.0f), R.drawable.msg_round_load_m);
            chat_fileStatesDrawable[3][0] = createCircleDrawableWithIcon(AndroidUtilities.dp(44.0f), R.drawable.msg_round_file_s);
            chat_fileStatesDrawable[3][1] = createCircleDrawableWithIcon(AndroidUtilities.dp(44.0f), R.drawable.msg_round_file_s);
            chat_fileStatesDrawable[4][0] = createCircleDrawableWithIcon(AndroidUtilities.dp(44.0f), R.drawable.msg_round_cancel_m);
            chat_fileStatesDrawable[4][1] = createCircleDrawableWithIcon(AndroidUtilities.dp(44.0f), R.drawable.msg_round_cancel_m);
            chat_fileStatesDrawable[5][0] = createCircleDrawableWithIcon(AndroidUtilities.dp(44.0f), R.drawable.msg_round_play_m);
            chat_fileStatesDrawable[5][1] = createCircleDrawableWithIcon(AndroidUtilities.dp(44.0f), R.drawable.msg_round_play_m);
            chat_fileStatesDrawable[6][0] = createCircleDrawableWithIcon(AndroidUtilities.dp(44.0f), R.drawable.msg_round_pause_m);
            chat_fileStatesDrawable[6][1] = createCircleDrawableWithIcon(AndroidUtilities.dp(44.0f), R.drawable.msg_round_pause_m);
            chat_fileStatesDrawable[7][0] = createCircleDrawableWithIcon(AndroidUtilities.dp(44.0f), R.drawable.msg_round_load_m);
            chat_fileStatesDrawable[7][1] = createCircleDrawableWithIcon(AndroidUtilities.dp(44.0f), R.drawable.msg_round_load_m);
            chat_fileStatesDrawable[8][0] = createCircleDrawableWithIcon(AndroidUtilities.dp(44.0f), R.drawable.msg_round_file_s);
            chat_fileStatesDrawable[8][1] = createCircleDrawableWithIcon(AndroidUtilities.dp(44.0f), R.drawable.msg_round_file_s);
            chat_fileStatesDrawable[9][0] = createCircleDrawableWithIcon(AndroidUtilities.dp(44.0f), R.drawable.msg_round_cancel_m);
            chat_fileStatesDrawable[9][1] = createCircleDrawableWithIcon(AndroidUtilities.dp(44.0f), R.drawable.msg_round_cancel_m);
            chat_photoStatesDrawables[0][0] = createCircleDrawableWithIcon(AndroidUtilities.dp(48.0f), R.drawable.msg_round_load_m);
            chat_photoStatesDrawables[0][1] = createCircleDrawableWithIcon(AndroidUtilities.dp(48.0f), R.drawable.msg_round_load_m);
            chat_photoStatesDrawables[1][0] = createCircleDrawableWithIcon(AndroidUtilities.dp(48.0f), R.drawable.msg_round_cancel_m);
            chat_photoStatesDrawables[1][1] = createCircleDrawableWithIcon(AndroidUtilities.dp(48.0f), R.drawable.msg_round_cancel_m);
            chat_photoStatesDrawables[2][0] = createCircleDrawableWithIcon(AndroidUtilities.dp(48.0f), R.drawable.msg_round_gif_m);
            chat_photoStatesDrawables[2][1] = createCircleDrawableWithIcon(AndroidUtilities.dp(48.0f), R.drawable.msg_round_gif_m);
            chat_photoStatesDrawables[3][0] = createCircleDrawableWithIcon(AndroidUtilities.dp(48.0f), R.drawable.msg_round_play_m);
            chat_photoStatesDrawables[3][1] = createCircleDrawableWithIcon(AndroidUtilities.dp(48.0f), R.drawable.msg_round_play_m);
            Drawable[][] drawableArr = chat_photoStatesDrawables;
            Drawable[] drawableArr2 = drawableArr[4];
            Drawable[] drawableArr3 = drawableArr[4];
            Drawable drawable = resources.getDrawable(R.drawable.burn);
            drawableArr3[1] = drawable;
            drawableArr2[0] = drawable;
            Drawable[][] drawableArr4 = chat_photoStatesDrawables;
            Drawable[] drawableArr5 = drawableArr4[5];
            Drawable[] drawableArr6 = drawableArr4[5];
            Drawable drawable2 = resources.getDrawable(R.drawable.circle);
            drawableArr6[1] = drawable2;
            drawableArr5[0] = drawable2;
            Drawable[][] drawableArr7 = chat_photoStatesDrawables;
            Drawable[] drawableArr8 = drawableArr7[6];
            Drawable[] drawableArr9 = drawableArr7[6];
            Drawable drawable3 = resources.getDrawable(R.drawable.photocheck);
            drawableArr9[1] = drawable3;
            drawableArr8[0] = drawable3;
            chat_photoStatesDrawables[7][0] = createCircleDrawableWithIcon(AndroidUtilities.dp(48.0f), R.drawable.msg_round_load_m);
            chat_photoStatesDrawables[7][1] = createCircleDrawableWithIcon(AndroidUtilities.dp(48.0f), R.drawable.msg_round_load_m);
            chat_photoStatesDrawables[8][0] = createCircleDrawableWithIcon(AndroidUtilities.dp(48.0f), R.drawable.msg_round_cancel_m);
            chat_photoStatesDrawables[8][1] = createCircleDrawableWithIcon(AndroidUtilities.dp(48.0f), R.drawable.msg_round_cancel_m);
            chat_photoStatesDrawables[9][0] = resources.getDrawable(R.drawable.doc_big).mutate();
            chat_photoStatesDrawables[9][1] = resources.getDrawable(R.drawable.doc_big).mutate();
            chat_photoStatesDrawables[10][0] = createCircleDrawableWithIcon(AndroidUtilities.dp(48.0f), R.drawable.msg_round_load_m);
            chat_photoStatesDrawables[10][1] = createCircleDrawableWithIcon(AndroidUtilities.dp(48.0f), R.drawable.msg_round_load_m);
            chat_photoStatesDrawables[11][0] = createCircleDrawableWithIcon(AndroidUtilities.dp(48.0f), R.drawable.msg_round_cancel_m);
            chat_photoStatesDrawables[11][1] = createCircleDrawableWithIcon(AndroidUtilities.dp(48.0f), R.drawable.msg_round_cancel_m);
            chat_photoStatesDrawables[12][0] = resources.getDrawable(R.drawable.doc_big).mutate();
            chat_photoStatesDrawables[12][1] = resources.getDrawable(R.drawable.doc_big).mutate();
            chat_contactDrawable[0] = createCircleDrawableWithIcon(AndroidUtilities.dp(44.0f), R.drawable.msg_contact);
            chat_contactDrawable[1] = createCircleDrawableWithIcon(AndroidUtilities.dp(44.0f), R.drawable.msg_contact);
            chat_locationDrawable[0] = createRoundRectDrawableWithIcon(AndroidUtilities.dp(2.0f), R.drawable.msg_location);
            chat_locationDrawable[1] = createRoundRectDrawableWithIcon(AndroidUtilities.dp(2.0f), R.drawable.msg_location);
            chat_composeShadowDrawable = context.getResources().getDrawable(R.drawable.compose_panel_shadow);
            try {
                int bitmapSize = AndroidUtilities.dp(6.0f) + AndroidUtilities.roundMessageSize;
                Bitmap bitmap = Bitmap.createBitmap(bitmapSize, bitmapSize, Bitmap.Config.ARGB_8888);
                Canvas canvas = new Canvas(bitmap);
                Paint eraserPaint = new Paint(1);
                eraserPaint.setColor(0);
                eraserPaint.setStyle(Paint.Style.FILL);
                eraserPaint.setXfermode(new PorterDuffXfermode(PorterDuff.Mode.CLEAR));
                Paint paint8 = new Paint(1);
                paint8.setShadowLayer(AndroidUtilities.dp(4.0f), 0.0f, 0.0f, 1593835520);
                int a = 0;
                while (a < 2) {
                    canvas.drawCircle(bitmapSize / 2, bitmapSize / 2, (AndroidUtilities.roundMessageSize / 2) - AndroidUtilities.dp(1.0f), a == 0 ? paint8 : eraserPaint);
                    a++;
                }
                try {
                    canvas.setBitmap(null);
                } catch (Exception e) {
                }
                chat_roundVideoShadow = new BitmapDrawable(bitmap);
            } catch (Throwable th) {
            }
            applyChatTheme(fontsOnly);
        }
        chat_msgTextPaintOneEmoji.setTextSize(AndroidUtilities.dp(28.0f));
        chat_msgTextPaintTwoEmoji.setTextSize(AndroidUtilities.dp(24.0f));
        chat_msgTextPaintThreeEmoji.setTextSize(AndroidUtilities.dp(20.0f));
        chat_msgTextPaint.setTextSize(AndroidUtilities.dp(SharedConfig.fontSize));
        chat_captionTextPaint.setTextSize(AndroidUtilities.dp(SharedConfig.fontSize));
        chat_msgGameTextPaint.setTextSize(AndroidUtilities.dp(14.0f));
        chat_msgBotButtonPaint.setTextSize(AndroidUtilities.dp(15.0f));
        if (!fontsOnly && (paint = chat_botProgressPaint) != null) {
            paint.setStrokeWidth(AndroidUtilities.dp(2.0f));
            chat_infoPaint.setTextSize(AndroidUtilities.dp(12.0f));
            chat_docNamePaint.setTextSize(AndroidUtilities.dp(13.5f));
            chat_locationTitlePaint.setTextSize(AndroidUtilities.dp(15.0f));
            chat_locationAddressPaint.setTextSize(AndroidUtilities.dp(13.0f));
            chat_audioTimePaint.setTextSize(AndroidUtilities.dp(12.0f));
            chat_livePaint.setTextSize(AndroidUtilities.dp(12.0f));
            chat_audioTitlePaint.setTextSize(AndroidUtilities.dp(16.0f));
            chat_audioPerformerPaint.setTextSize(AndroidUtilities.dp(15.0f));
            chat_botButtonPaint.setTextSize(AndroidUtilities.dp(15.0f));
            chat_contactNamePaint.setTextSize(AndroidUtilities.dp(15.0f));
            chat_contactPhonePaint.setTextSize(AndroidUtilities.dp(13.0f));
            chat_durationPaint.setTextSize(AndroidUtilities.dp(12.0f));
            chat_timePaint.setTextSize(AndroidUtilities.dp(12.0f));
            chat_adminPaint.setTextSize(AndroidUtilities.dp(13.0f));
            chat_namePaint.setTextSize(AndroidUtilities.dp(11.0f));
            chat_forwardNamePaint.setTextSize(AndroidUtilities.dp(14.0f));
            chat_replyNamePaint.setTextSize(AndroidUtilities.dp(14.0f));
            chat_replyTextPaint.setTextSize(AndroidUtilities.dp(14.0f));
            chat_redpkgTextPaint.setTextSize(AndroidUtilities.dp(14.0f));
            chat_gamePaint.setTextSize(AndroidUtilities.dp(13.0f));
            chat_shipmentPaint.setTextSize(AndroidUtilities.dp(13.0f));
            chat_instantViewPaint.setTextSize(AndroidUtilities.dp(13.0f));
            chat_instantViewRectPaint.setStrokeWidth(AndroidUtilities.dp(1.0f));
            chat_statusRecordPaint.setStrokeWidth(AndroidUtilities.dp(2.0f));
            chat_actionTextPaint.setTextSize(AndroidUtilities.dp(14.0f));
            chat_contextResult_titleTextPaint.setTextSize(AndroidUtilities.dp(15.0f));
            chat_contextResult_descriptionTextPaint.setTextSize(AndroidUtilities.dp(13.0f));
            chat_radialProgressPaint.setStrokeWidth(AndroidUtilities.dp(3.0f));
            chat_radialProgress2Paint.setStrokeWidth(AndroidUtilities.dp(2.0f));
            chat_translationPaint.setTextSize(AndroidUtilities.dp(10.0f));
        }
    }

    public static void applyChatTheme(boolean fontsOnly) {
        if (chat_msgTextPaint != null && chat_msgInDrawable != null && !fontsOnly) {
            chat_gamePaint.setColor(getColor(key_chat_previewGameText));
            chat_durationPaint.setColor(getColor(key_chat_previewDurationText));
            chat_botButtonPaint.setColor(getColor(key_chat_botButtonText));
            chat_urlPaint.setColor(getColor(key_chat_linkSelectBackground));
            chat_botProgressPaint.setColor(getColor(key_chat_botProgress));
            chat_deleteProgressPaint.setColor(getColor(key_chat_secretTimeText));
            chat_textSearchSelectionPaint.setColor(getColor(key_chat_textSelectBackground));
            chat_msgErrorPaint.setColor(getColor(key_chat_sentError));
            chat_statusPaint.setColor(getColor(key_chat_status));
            chat_statusRecordPaint.setColor(getColor(key_chat_status));
            chat_actionTextPaint.setColor(getColor(key_chat_serviceText));
            chat_actionTextPaint.linkColor = getColor(key_chat_serviceLink);
            chat_contextResult_titleTextPaint.setColor(getColor(key_windowBackgroundWhiteBlackText));
            chat_composeBackgroundPaint.setColor(getColor(key_chat_messagePanelBackground));
            chat_timeBackgroundPaint.setColor(getColor(key_chat_mediaTimeBackground));
            chat_actionBackgroundPaint2.setColor(getColor(key_chats_sersviceBackground));
            setDrawableColor(chat_msgRedpkgInDrawable, -1);
            setDrawableColor(chat_msgRedpkgInSelectedDrawable, -1);
            setDrawableColor(chat_msgRedpkgOutDrawable, -1);
            setDrawableColor(chat_msgRedpkgOutSelectedDrawable, -1);
            setDrawableColor(chat_msgRedpkgInMediaDrawable, -1);
            setDrawableColor(chat_msgRedpkgInMediaSelectedDrawable, -1);
            setDrawableColor(chat_msgRedpkgOutMediaDrawable, -1);
            setDrawableColor(chat_msgRedpkgOutMediaSelectedDrawable, -1);
            setDrawableColorByKey(chat_msgNoSoundDrawable, key_chat_mediaTimeText);
            setDrawableColorByKey(chat_msgInDrawable, key_chat_inBubble);
            setDrawableColorByKey(chat_msgInSelectedDrawable, key_chat_inBubbleSelected);
            setDrawableColorByKey(chat_msgInShadowDrawable, key_chat_inBubbleShadow);
            setDrawableColorByKey(chat_msgOutDrawable, key_chat_outBubble);
            setDrawableColorByKey(chat_msgOutSelectedDrawable, key_chat_outBubbleSelected);
            setDrawableColorByKey(chat_msgOutShadowDrawable, key_chat_outBubbleShadow);
            setDrawableColorByKey(chat_msgInMediaDrawable, key_chat_inBubble);
            setDrawableColorByKey(chat_msgInMediaSelectedDrawable, key_chat_inBubbleSelected);
            setDrawableColorByKey(chat_msgInMediaShadowDrawable, key_chat_inBubbleShadow);
            setDrawableColorByKey(chat_msgOutMediaDrawable, key_chat_outBubble);
            setDrawableColorByKey(chat_msgOutMediaSelectedDrawable, key_chat_outBubbleSelected);
            setDrawableColorByKey(chat_msgOutMediaShadowDrawable, key_chat_outMediaBubbleShadow);
            setDrawableColorByKey(chat_msgOutCheckDrawable, key_chat_outSentCheck);
            setDrawableColorByKey(chat_msgOutCheckSelectedDrawable, key_chat_outSentCheckSelected);
            setDrawableColorByKey(chat_msgOutCheckReadDrawable, key_chat_outSentCheckRead);
            setDrawableColorByKey(chat_msgOutCheckReadSelectedDrawable, key_chat_outSentCheckReadSelected);
            setDrawableColorByKey(chat_msgOutHalfCheckDrawable, key_chat_outSentCheckRead);
            setDrawableColorByKey(chat_msgOutHalfCheckSelectedDrawable, key_chat_outSentCheckReadSelected);
            setDrawableColorByKey(chat_msgOutClockDrawable, key_chat_outSentClock);
            setDrawableColorByKey(chat_msgOutSelectedClockDrawable, key_chat_outSentClockSelected);
            setDrawableColorByKey(chat_msgOutAudioFlagIcon, key_chat_outVoiceIcon);
            setDrawableColorByKey(chat_msgInAudioFlagIcon, key_chat_inVoiceIcon);
            setDrawableColor(chat_msgOutGrayClockDrawable, -6710887);
            setDrawableColor(chat_msgOutGraySelectedClockDrawable, -6710887);
            setDrawableColor(chat_msgOutHalfGrayCheckDrawable, -1);
            setDrawableColor(chat_msgOutHalfGrayCheckSelectedDrawable, -1);
            setDrawableColor(chat_msgMediaHalfGrayCheckDrawable, -12862209);
            setDrawableColor(chat_msgStickerHalfGrayCheckDrawable, -12862209);
            setDrawableColor(chat_msgOutCheckGrayDrawable, -1);
            setDrawableColor(chat_msgOutCheckGraySelectedDrawable, -1);
            setDrawableColor(chat_msgOutCheckReadGrayDrawable, -1);
            setDrawableColor(chat_msgOutCheckReadGraySelectedDrawable, -1);
            setDrawableColorByKey(chat_msgInClockDrawable, key_chat_inSentClock);
            setDrawableColorByKey(chat_msgInSelectedClockDrawable, key_chat_inSentClockSelected);
            setDrawableColorByKey(chat_msgMediaCheckDrawable, key_chat_mediaSentCheck);
            setDrawableColorByKey(chat_msgMediaHalfCheckDrawable, key_chat_mediaSentCheck);
            setDrawableColorByKey(chat_msgMediaClockDrawable, key_chat_mediaSentClock);
            setDrawableColorByKey(chat_msgStickerCheckDrawable, key_chat_serviceText);
            setDrawableColorByKey(chat_msgStickerHalfCheckDrawable, key_chat_serviceText);
            setDrawableColorByKey(chat_msgStickerClockDrawable, key_chat_serviceText);
            setDrawableColorByKey(chat_msgStickerViewsDrawable, key_chat_serviceText);
            setDrawableColorByKey(chat_shareIconDrawable, key_chat_serviceIcon);
            setDrawableColorByKey(chat_replyIconDrawable, key_chat_serviceIcon);
            setDrawableColorByKey(chat_goIconDrawable, key_chat_serviceIcon);
            setDrawableColorByKey(chat_botInlineDrawable, key_chat_serviceIcon);
            setDrawableColorByKey(chat_botLinkDrawalbe, key_chat_serviceIcon);
            setDrawableColorByKey(chat_msgInViewsDrawable, key_chat_inViews);
            setDrawableColorByKey(chat_msgInViewsSelectedDrawable, key_chat_inViewsSelected);
            setDrawableColorByKey(chat_msgOutViewsDrawable, key_chat_outViews);
            setDrawableColorByKey(chat_msgOutViewsSelectedDrawable, key_chat_outViewsSelected);
            setDrawableColorByKey(chat_msgMediaViewsDrawable, key_chat_mediaViews);
            setDrawableColorByKey(chat_msgInMenuDrawable, key_chat_inMenu);
            setDrawableColorByKey(chat_msgInMenuSelectedDrawable, key_chat_inMenuSelected);
            setDrawableColorByKey(chat_msgOutMenuDrawable, key_chat_outMenu);
            setDrawableColorByKey(chat_msgOutMenuSelectedDrawable, key_chat_outMenuSelected);
            setDrawableColorByKey(chat_msgMediaMenuDrawable, key_chat_mediaMenu);
            setDrawableColorByKey(chat_msgOutInstantDrawable, key_chat_outInstant);
            setDrawableColorByKey(chat_msgInInstantDrawable, key_chat_inInstant);
            setDrawableColorByKey(chat_msgErrorDrawable, key_chat_sentErrorIcon);
            setDrawableColorByKey(chat_muteIconDrawable, key_chat_muteIcon);
            setDrawableColorByKey(chat_lockIconDrawable, key_chat_lockIcon);
            setDrawableColorByKey(chat_msgBroadcastDrawable, key_chat_outBroadcast);
            setDrawableColorByKey(chat_msgBroadcastMediaDrawable, key_chat_mediaBroadcast);
            setDrawableColorByKey(chat_inlineResultFile, key_chat_inlineResultIcon);
            setDrawableColorByKey(chat_inlineResultAudio, key_chat_inlineResultIcon);
            setDrawableColorByKey(chat_inlineResultLocation, key_chat_inlineResultIcon);
            setDrawableColorByKey(chat_msgInCallDrawable, key_chat_inInstant);
            setDrawableColorByKey(chat_msgInCallSelectedDrawable, key_chat_inInstantSelected);
            setDrawableColorByKey(chat_msgOutCallDrawable, key_chat_outInstant);
            setDrawableColorByKey(chat_msgOutCallSelectedDrawable, key_chat_outInstantSelected);
            setDrawableColor(chat_msgOutVideoCallDrawable, -1);
            setDrawableColor(chat_msgOutVoiceCallDrawable, -1);
            setDrawableColor(chat_msgVideoCallDrawable, -16777216);
            setDrawableColor(chat_msgVoiceCallDrawable, -16777216);
            setDrawableColorByKey(chat_msgCallUpGreenDrawable, key_chat_outGreenCall);
            setDrawableColorByKey(chat_msgCallDownRedDrawable, key_chat_inRedCall);
            setDrawableColorByKey(chat_msgCallDownGreenDrawable, key_chat_inGreenCall);
            setDrawableColorByKey(calllog_msgCallUpRedDrawable, key_calls_callReceivedRedIcon);
            setDrawableColorByKey(calllog_msgCallUpGreenDrawable, key_calls_callReceivedGreenIcon);
            setDrawableColorByKey(calllog_msgCallDownRedDrawable, key_calls_callReceivedRedIcon);
            setDrawableColorByKey(calllog_msgCallDownGreenDrawable, key_calls_callReceivedGreenIcon);
            for (int a = 0; a < 2; a++) {
                setCombinedDrawableColor(chat_fileMiniStatesDrawable[a][0], getColor(key_chat_outLoader), false);
                setCombinedDrawableColor(chat_fileMiniStatesDrawable[a][0], getColor(key_chat_outMediaIcon), true);
                setCombinedDrawableColor(chat_fileMiniStatesDrawable[a][1], getColor(key_chat_outLoaderSelected), false);
                setCombinedDrawableColor(chat_fileMiniStatesDrawable[a][1], getColor(key_chat_outMediaIconSelected), true);
                setCombinedDrawableColor(chat_fileMiniStatesDrawable[a + 2][0], getColor(key_chat_inLoader), false);
                setCombinedDrawableColor(chat_fileMiniStatesDrawable[a + 2][0], getColor(key_chat_inMediaIcon), true);
                setCombinedDrawableColor(chat_fileMiniStatesDrawable[a + 2][1], getColor(key_chat_inLoaderSelected), false);
                setCombinedDrawableColor(chat_fileMiniStatesDrawable[a + 2][1], getColor(key_chat_inMediaIconSelected), true);
                setCombinedDrawableColor(chat_fileMiniStatesDrawable[a + 4][0], getColor(key_chat_mediaLoaderPhoto), false);
                setCombinedDrawableColor(chat_fileMiniStatesDrawable[a + 4][0], getColor(key_chat_mediaLoaderPhotoIcon), true);
                setCombinedDrawableColor(chat_fileMiniStatesDrawable[a + 4][1], getColor(key_chat_mediaLoaderPhotoSelected), false);
                setCombinedDrawableColor(chat_fileMiniStatesDrawable[a + 4][1], getColor(key_chat_mediaLoaderPhotoIconSelected), true);
            }
            for (int a2 = 0; a2 < 5; a2++) {
                setCombinedDrawableColor(chat_fileStatesDrawable[a2][0], getColor(key_chat_outLoader), false);
                setCombinedDrawableColor(chat_fileStatesDrawable[a2][0], getColor(key_chat_outMediaIcon), true);
                setCombinedDrawableColor(chat_fileStatesDrawable[a2][1], getColor(key_chat_outLoaderSelected), false);
                setCombinedDrawableColor(chat_fileStatesDrawable[a2][1], getColor(key_chat_outMediaIconSelected), true);
                setCombinedDrawableColor(chat_fileStatesDrawable[a2 + 5][0], getColor(key_chat_inLoader), false);
                setCombinedDrawableColor(chat_fileStatesDrawable[a2 + 5][0], getColor(key_chat_inMediaIcon), true);
                setCombinedDrawableColor(chat_fileStatesDrawable[a2 + 5][1], getColor(key_chat_inLoaderSelected), false);
                setCombinedDrawableColor(chat_fileStatesDrawable[a2 + 5][1], getColor(key_chat_inMediaIconSelected), true);
            }
            for (int a3 = 0; a3 < 4; a3++) {
                setCombinedDrawableColor(chat_photoStatesDrawables[a3][0], getColor(key_chat_mediaLoaderPhoto), false);
                setCombinedDrawableColor(chat_photoStatesDrawables[a3][0], getColor(key_chat_mediaLoaderPhotoIcon), true);
                setCombinedDrawableColor(chat_photoStatesDrawables[a3][1], getColor(key_chat_mediaLoaderPhotoSelected), false);
                setCombinedDrawableColor(chat_photoStatesDrawables[a3][1], getColor(key_chat_mediaLoaderPhotoIconSelected), true);
            }
            for (int a4 = 0; a4 < 2; a4++) {
                setCombinedDrawableColor(chat_photoStatesDrawables[a4 + 7][0], getColor(key_chat_outLoaderPhoto), false);
                setCombinedDrawableColor(chat_photoStatesDrawables[a4 + 7][0], getColor(key_chat_outLoaderPhotoIcon), true);
                setCombinedDrawableColor(chat_photoStatesDrawables[a4 + 7][1], getColor(key_chat_outLoaderPhotoSelected), false);
                setCombinedDrawableColor(chat_photoStatesDrawables[a4 + 7][1], getColor(key_chat_outLoaderPhotoIconSelected), true);
                setCombinedDrawableColor(chat_photoStatesDrawables[a4 + 10][0], getColor(key_chat_inLoaderPhoto), false);
                setCombinedDrawableColor(chat_photoStatesDrawables[a4 + 10][0], getColor(key_chat_inLoaderPhotoIcon), true);
                setCombinedDrawableColor(chat_photoStatesDrawables[a4 + 10][1], getColor(key_chat_inLoaderPhotoSelected), false);
                setCombinedDrawableColor(chat_photoStatesDrawables[a4 + 10][1], getColor(key_chat_inLoaderPhotoIconSelected), true);
            }
            setDrawableColorByKey(chat_photoStatesDrawables[9][0], key_chat_outFileIcon);
            setDrawableColorByKey(chat_photoStatesDrawables[9][1], key_chat_outFileSelectedIcon);
            setDrawableColorByKey(chat_photoStatesDrawables[12][0], key_chat_inFileIcon);
            setDrawableColorByKey(chat_photoStatesDrawables[12][1], key_chat_inFileSelectedIcon);
            setCombinedDrawableColor(chat_contactDrawable[0], getColor(key_chat_inContactBackground), false);
            setCombinedDrawableColor(chat_contactDrawable[0], getColor(key_chat_inContactIcon), true);
            setCombinedDrawableColor(chat_contactDrawable[1], getColor(key_chat_outContactBackground), false);
            setCombinedDrawableColor(chat_contactDrawable[1], getColor(key_chat_outContactIcon), true);
            setCombinedDrawableColor(chat_locationDrawable[0], getColor(key_chat_inLocationBackground), false);
            setCombinedDrawableColor(chat_locationDrawable[0], getColor(key_chat_inLocationIcon), true);
            setCombinedDrawableColor(chat_locationDrawable[1], getColor(key_chat_outLocationBackground), false);
            setCombinedDrawableColor(chat_locationDrawable[1], getColor(key_chat_outLocationIcon), true);
            setDrawableColorByKey(chat_composeShadowDrawable, key_chat_messagePanelShadow);
            setCombinedDrawableColor(chat_attachButtonDrawables[0], getColor(key_chat_attachGalleryBackground), false);
            setCombinedDrawableColor(chat_attachButtonDrawables[0], getColor(key_chat_attachGalleryIcon), true);
            setCombinedDrawableColor(chat_attachButtonDrawables[1], getColor(key_chat_attachAudioBackground), false);
            setCombinedDrawableColor(chat_attachButtonDrawables[1], getColor(key_chat_attachAudioIcon), true);
            setCombinedDrawableColor(chat_attachButtonDrawables[2], getColor(key_chat_attachFileBackground), false);
            setCombinedDrawableColor(chat_attachButtonDrawables[2], getColor(key_chat_attachFileIcon), true);
            setCombinedDrawableColor(chat_attachButtonDrawables[3], getColor(key_chat_attachContactBackground), false);
            setCombinedDrawableColor(chat_attachButtonDrawables[3], getColor(key_chat_attachContactIcon), true);
            setCombinedDrawableColor(chat_attachButtonDrawables[4], getColor(key_chat_attachLocationBackground), false);
            setCombinedDrawableColor(chat_attachButtonDrawables[4], getColor(key_chat_attachLocationIcon), true);
            setCombinedDrawableColor(chat_attachButtonDrawables[5], getColor(key_chat_attachPollBackground), false);
            setCombinedDrawableColor(chat_attachButtonDrawables[5], getColor(key_chat_attachPollIcon), true);
            setDrawableColor(chat_attachEmptyDrawable, getColor(key_chat_attachEmptyImage));
            applyChatServiceMessageColor();
        }
    }

    public static void applyChatServiceMessageColor() {
        applyChatServiceMessageColor(null);
    }

    public static void applyChatServiceMessageColor(int[] custom) {
        Integer serviceColor;
        Integer servicePressedColor;
        if (chat_actionBackgroundPaint == null) {
            return;
        }
        serviceMessageColor = serviceMessageColorBackup;
        serviceSelectedMessageColor = serviceSelectedMessageColorBackup;
        if (custom != null && custom.length >= 2) {
            serviceColor = Integer.valueOf(custom[0]);
            servicePressedColor = Integer.valueOf(custom[1]);
            serviceMessageColor = custom[0];
            serviceSelectedMessageColor = custom[1];
        } else {
            serviceColor = currentColors.get(key_chat_serviceBackground);
            servicePressedColor = currentColors.get(key_chat_serviceBackgroundSelected);
        }
        Integer serviceColor2 = serviceColor;
        Integer servicePressedColor2 = servicePressedColor;
        if (serviceColor == null) {
            serviceColor = Integer.valueOf(serviceMessageColor);
            serviceColor2 = Integer.valueOf(serviceMessage2Color);
        }
        if (servicePressedColor == null) {
            servicePressedColor = Integer.valueOf(serviceSelectedMessageColor);
            servicePressedColor2 = Integer.valueOf(serviceSelectedMessage2Color);
        }
        if (currentColor != serviceColor.intValue()) {
            chat_actionBackgroundPaint.setColor(serviceColor.intValue());
            colorFilter = new PorterDuffColorFilter(serviceColor.intValue(), PorterDuff.Mode.MULTIPLY);
            colorFilter2 = new PorterDuffColorFilter(serviceColor2.intValue(), PorterDuff.Mode.MULTIPLY);
            currentColor = serviceColor.intValue();
            if (chat_cornerOuter[0] != null) {
                for (int a = 0; a < 4; a++) {
                    chat_cornerOuter[a].setColorFilter(colorFilter);
                    chat_cornerInner[a].setColorFilter(colorFilter);
                }
            }
        }
        int a2 = currentSelectedColor;
        if (a2 != servicePressedColor.intValue()) {
            currentSelectedColor = servicePressedColor.intValue();
            colorPressedFilter = new PorterDuffColorFilter(servicePressedColor.intValue(), PorterDuff.Mode.MULTIPLY);
            colorPressedFilter2 = new PorterDuffColorFilter(servicePressedColor2.intValue(), PorterDuff.Mode.MULTIPLY);
        }
    }

    public static void createProfileResources(Context context) {
        if (profile_verifiedDrawable == null) {
            profile_aboutTextPaint = new TextPaint(1);
            Resources resources = context.getResources();
            profile_verifiedDrawable = resources.getDrawable(R.drawable.verified_area).mutate();
            profile_verifiedCheckDrawable = resources.getDrawable(R.drawable.verified_check).mutate();
            applyProfileTheme();
        }
        profile_aboutTextPaint.setTextSize(AndroidUtilities.dp(16.0f));
    }

    public static ColorFilter getShareColorFilter(int color, boolean selected) {
        if (selected) {
            if (currentShareSelectedColorFilter == null || currentShareSelectedColorFilterColor != color) {
                currentShareSelectedColorFilterColor = color;
                currentShareSelectedColorFilter = new PorterDuffColorFilter(color, PorterDuff.Mode.MULTIPLY);
            }
            return currentShareSelectedColorFilter;
        }
        if (currentShareColorFilter == null || currentShareColorFilterColor != color) {
            currentShareColorFilterColor = color;
            currentShareColorFilter = new PorterDuffColorFilter(color, PorterDuff.Mode.MULTIPLY);
        }
        return currentShareColorFilter;
    }

    public static void applyProfileTheme() {
        if (profile_verifiedDrawable == null) {
            return;
        }
        profile_aboutTextPaint.setColor(getColor(key_windowBackgroundWhiteBlackText));
        profile_aboutTextPaint.linkColor = getColor(key_windowBackgroundWhiteLinkText);
        setDrawableColorByKey(profile_verifiedDrawable, key_profile_verifiedBackground);
        setDrawableColorByKey(profile_verifiedCheckDrawable, key_profile_verifiedCheck);
    }

    public static Drawable getThemedDrawable(Context context, int resId, String key) {
        return getThemedDrawable(context, resId, getColor(key));
    }

    public static Drawable getThemedDrawable(Context context, int resId, int color) {
        if (context == null) {
            return null;
        }
        Drawable drawable = context.getResources().getDrawable(resId).mutate();
        drawable.setColorFilter(new PorterDuffColorFilter(color, PorterDuff.Mode.MULTIPLY));
        return drawable;
    }

    public static int getDefaultColor(String key) {
        Integer value = defaultColors.get(key);
        if (value == null) {
            if (key.equals(key_chats_menuTopShadow) || key.equals(key_chats_menuTopBackground)) {
                return 0;
            }
            return SupportMenu.CATEGORY_MASK;
        }
        return value.intValue();
    }

    public static boolean hasThemeKey(String key) {
        return currentColors.containsKey(key);
    }

    public static Integer getColorOrNull(String key) {
        Integer color = currentColors.get(key);
        if (color == null) {
            String fallbackKey = fallbackKeys.get(key);
            if (fallbackKey != null) {
                color = currentColors.get(key);
            }
            if (color == null) {
                return defaultColors.get(key);
            }
            return color;
        }
        return color;
    }

    public static void setAnimatingColor(boolean animating) {
        animatingColors = animating ? new HashMap<>() : null;
    }

    public static boolean isAnimatingColor() {
        return animatingColors != null;
    }

    public static void setAnimatedColor(String key, int value) {
        HashMap<String, Integer> map = animatingColors;
        if (map == null) {
            return;
        }
        map.put(key, Integer.valueOf(value));
    }

    public static int getColor(String key) {
        return getColor(key, null);
    }

    public static int getColor(String key, boolean[] isDefault) {
        Integer color;
        HashMap<String, Integer> map = animatingColors;
        if (map != null && (color = map.get(key)) != null) {
            return color.intValue();
        }
        if (isCurrentThemeDefault()) {
            if (key.equals(key_chat_serviceBackground)) {
                return serviceMessageColor;
            }
            if (key.equals(key_chat_serviceBackgroundSelected)) {
                return serviceSelectedMessageColor;
            }
            return getDefaultColor(key);
        }
        Integer color2 = currentColors.get(key);
        if (color2 == null) {
            String fallbackKey = fallbackKeys.get(key);
            if (fallbackKey != null) {
                color2 = currentColors.get(fallbackKey);
            }
            if (color2 == null) {
                if (isDefault != null) {
                    isDefault[0] = true;
                }
                if (key.equals(key_chat_serviceBackground)) {
                    return serviceMessageColor;
                }
                if (key.equals(key_chat_serviceBackgroundSelected)) {
                    return serviceSelectedMessageColor;
                }
                return getDefaultColor(key);
            }
        }
        return color2.intValue();
    }

    public static void setColor(String key, int color, boolean useDefault) {
        if (key.equals(key_chat_wallpaper) || key.equals(key_chat_wallpaper_gradient_to)) {
            color |= -16777216;
        }
        if (useDefault) {
            currentColors.remove(key);
        } else {
            currentColors.put(key, Integer.valueOf(color));
        }
        if (key.equals(key_chat_serviceBackground) || key.equals(key_chat_serviceBackgroundSelected)) {
            applyChatServiceMessageColor();
        } else if (key.equals(key_chat_wallpaper) || key.equals(key_chat_wallpaper_gradient_to)) {
            reloadWallpaper();
        }
    }

    public static void setThemeWallpaper(ThemeInfo themeInfo, Bitmap bitmap, File path) throws Throwable {
        currentColors.remove(key_chat_wallpaper);
        currentColors.remove(key_chat_wallpaper_gradient_to);
        themedWallpaperLink = null;
        MessagesController.getGlobalMainSettings().edit().remove("overrideThemeWallpaper").commit();
        if (bitmap != null) {
            themedWallpaper = new BitmapDrawable(bitmap);
            saveCurrentTheme(themeInfo, false, false, false);
            calcBackgroundColor(themedWallpaper, 0);
            applyChatServiceMessageColor();
            NotificationCenter.getGlobalInstance().postNotificationName(NotificationCenter.didSetNewWallpapper, new Object[0]);
            return;
        }
        themedWallpaper = null;
        wallpaper = null;
        saveCurrentTheme(themeInfo, false, false, false);
        reloadWallpaper();
    }

    public static void setDrawableColor(Drawable drawable, int color) {
        if (drawable == null) {
            return;
        }
        if (drawable instanceof ShapeDrawable) {
            ((ShapeDrawable) drawable).getPaint().setColor(color);
        } else if (drawable instanceof ScamDrawable) {
            ((ScamDrawable) drawable).setColor(color);
        } else {
            drawable.setColorFilter(new PorterDuffColorFilter(color, PorterDuff.Mode.MULTIPLY));
        }
    }

    public static void setDrawableColorByKey(Drawable drawable, String key) {
        if (key == null) {
            return;
        }
        setDrawableColor(drawable, getColor(key));
    }

    public static void setEmojiDrawableColor(Drawable drawable, int color, boolean selected) {
        if (drawable instanceof StateListDrawable) {
            try {
                if (selected) {
                    Drawable state = getStateDrawable(drawable, 0);
                    if (state instanceof ShapeDrawable) {
                        ((ShapeDrawable) state).getPaint().setColor(color);
                    } else {
                        state.setColorFilter(new PorterDuffColorFilter(color, PorterDuff.Mode.MULTIPLY));
                    }
                    return;
                }
                Drawable state2 = getStateDrawable(drawable, 1);
                if (state2 instanceof ShapeDrawable) {
                    ((ShapeDrawable) state2).getPaint().setColor(color);
                } else {
                    state2.setColorFilter(new PorterDuffColorFilter(color, PorterDuff.Mode.MULTIPLY));
                }
            } catch (Throwable th) {
            }
        }
    }

    public static void setSelectorDrawableColor(Drawable drawable, int color, boolean selected) {
        if (drawable instanceof StateListDrawable) {
            try {
                if (selected) {
                    Drawable state = getStateDrawable(drawable, 0);
                    if (state instanceof ShapeDrawable) {
                        ((ShapeDrawable) state).getPaint().setColor(color);
                    } else {
                        state.setColorFilter(new PorterDuffColorFilter(color, PorterDuff.Mode.MULTIPLY));
                    }
                    Drawable state2 = getStateDrawable(drawable, 1);
                    if (state2 instanceof ShapeDrawable) {
                        ((ShapeDrawable) state2).getPaint().setColor(color);
                    } else {
                        state2.setColorFilter(new PorterDuffColorFilter(color, PorterDuff.Mode.MULTIPLY));
                    }
                    return;
                }
                Drawable state3 = getStateDrawable(drawable, 2);
                if (state3 instanceof ShapeDrawable) {
                    ((ShapeDrawable) state3).getPaint().setColor(color);
                    return;
                } else {
                    state3.setColorFilter(new PorterDuffColorFilter(color, PorterDuff.Mode.MULTIPLY));
                    return;
                }
            } catch (Throwable th) {
                return;
            }
        }
        if (Build.VERSION.SDK_INT >= 21 && (drawable instanceof RippleDrawable)) {
            RippleDrawable rippleDrawable = (RippleDrawable) drawable;
            if (selected) {
                rippleDrawable.setColor(new ColorStateList(new int[][]{StateSet.WILD_CARD}, new int[]{color}));
                return;
            }
            if (rippleDrawable.getNumberOfLayers() > 0) {
                Drawable drawable1 = rippleDrawable.getDrawable(0);
                if (drawable1 instanceof ShapeDrawable) {
                    ((ShapeDrawable) drawable1).getPaint().setColor(color);
                } else {
                    drawable1.setColorFilter(new PorterDuffColorFilter(color, PorterDuff.Mode.MULTIPLY));
                }
            }
        }
    }

    public static boolean isThemeWallpaperPublic() {
        return !TextUtils.isEmpty(themedWallpaperLink);
    }

    public static boolean hasWallpaperFromTheme() {
        return currentColors.containsKey(key_chat_wallpaper) || themedWallpaperFileOffset > 0 || !TextUtils.isEmpty(themedWallpaperLink);
    }

    public static boolean isCustomTheme() {
        return isCustomTheme;
    }

    public static int getSelectedColor() {
        return selectedColor;
    }

    public static void reloadWallpaper() {
        wallpaper = null;
        themedWallpaper = null;
        loadWallpaper();
    }

    private static void calcBackgroundColor(Drawable drawable, int save) {
        if (save != 2) {
            int[] result = AndroidUtilities.calcDrawableColor(drawable);
            int i = result[0];
            serviceMessageColorBackup = i;
            serviceMessageColor = i;
            int i2 = result[1];
            serviceSelectedMessageColorBackup = i2;
            serviceSelectedMessageColor = i2;
            serviceMessage2Color = result[2];
            serviceSelectedMessage2Color = result[3];
        }
    }

    public static int getServiceMessageColor() {
        Integer serviceColor = currentColors.get(key_chat_serviceBackground);
        return serviceColor == null ? serviceMessageColor : serviceColor.intValue();
    }

    public static void loadWallpaper() {
        if (wallpaper != null) {
            return;
        }
        Utilities.searchQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.ui.actionbar.-$$Lambda$Theme$axMG89yNkmpvICfd1CVPS7qkUYA
            @Override // java.lang.Runnable
            public final void run() {
                Theme.lambda$loadWallpaper$7();
            }
        });
    }

    static /* synthetic */ void lambda$loadWallpaper$7() {
        File file;
        synchronized (wallpaperSync) {
            SharedPreferences preferences = MessagesController.getGlobalMainSettings();
            boolean overrideTheme = previousTheme == null && preferences.getBoolean("overrideThemeWallpaper", false);
            isWallpaperMotion = preferences.getBoolean("selectedBackgroundMotion", false);
            isPatternWallpaper = preferences.getLong("selectedPattern", 0L) != 0;
            if (!overrideTheme) {
                Integer backgroundColor = currentColors.get(key_chat_wallpaper);
                if (backgroundColor != null) {
                    Integer gradientToColor = currentColors.get(key_chat_wallpaper_gradient_to);
                    if (gradientToColor == null) {
                        wallpaper = new ColorDrawable(backgroundColor.intValue());
                    } else {
                        wallpaper = new BackgroundGradientDrawable(GradientDrawable.Orientation.BL_TR, new int[]{backgroundColor.intValue(), gradientToColor.intValue()});
                    }
                    isCustomTheme = true;
                } else if (themedWallpaperLink != null) {
                    File pathToWallpaper = new File(ApplicationLoader.getFilesDirFixed(), Utilities.MD5(themedWallpaperLink) + ".wp");
                    Bitmap bitmap = BitmapFactory.decodeFile(pathToWallpaper.getAbsolutePath());
                    if (bitmap != null) {
                        BitmapDrawable bitmapDrawable = new BitmapDrawable(bitmap);
                        wallpaper = bitmapDrawable;
                        themedWallpaper = bitmapDrawable;
                        isCustomTheme = true;
                    }
                } else if (themedWallpaperFileOffset > 0 && (currentTheme.pathToFile != null || currentTheme.assetName != null)) {
                    FileInputStream stream = null;
                    try {
                        if (currentTheme.assetName != null) {
                            file = getAssetFile(currentTheme.assetName);
                        } else {
                            file = new File(currentTheme.pathToFile);
                        }
                        stream = new FileInputStream(file);
                        stream.getChannel().position(themedWallpaperFileOffset);
                        Bitmap bitmap2 = BitmapFactory.decodeStream(stream);
                        if (bitmap2 != null) {
                            BitmapDrawable bitmapDrawable2 = new BitmapDrawable(bitmap2);
                            wallpaper = bitmapDrawable2;
                            themedWallpaper = bitmapDrawable2;
                            isCustomTheme = true;
                        }
                        try {
                            stream.close();
                        } catch (Exception e) {
                            e = e;
                            FileLog.e(e);
                        }
                    } catch (Throwable e2) {
                        try {
                            FileLog.e(e2);
                            if (stream != null) {
                                try {
                                    stream.close();
                                } catch (Exception e3) {
                                    e = e3;
                                    FileLog.e(e);
                                }
                            }
                        } finally {
                        }
                    }
                }
            }
            if (wallpaper == null) {
                int selectedColor2 = 0;
                try {
                    long selectedBackground = getSelectedBackgroundId();
                    long selectedPattern = preferences.getLong("selectedPattern", 0L);
                    selectedColor2 = preferences.getInt("selectedColor", 0);
                    if (selectedBackground == DEFAULT_BACKGROUND_ID) {
                        wallpaper = ApplicationLoader.applicationContext.getResources().getDrawable(R.drawable.background_hd);
                        isCustomTheme = false;
                    } else if (selectedBackground == -1 || selectedBackground < -100 || selectedBackground > 0) {
                        if (selectedColor2 != 0 && selectedPattern == 0) {
                            wallpaper = new ColorDrawable(selectedColor2);
                        } else {
                            File toFile = new File(ApplicationLoader.getFilesDirFixed(), "wallpaper.jpg");
                            toFile.length();
                            if (toFile.exists()) {
                                wallpaper = Drawable.createFromPath(toFile.getAbsolutePath());
                                isCustomTheme = true;
                            } else {
                                wallpaper = ApplicationLoader.applicationContext.getResources().getDrawable(R.drawable.background_hd);
                                isCustomTheme = false;
                            }
                        }
                    }
                } catch (Throwable th) {
                }
                if (wallpaper == null) {
                    if (selectedColor2 == 0) {
                        selectedColor2 = -2693905;
                    }
                    wallpaper = new ColorDrawable(selectedColor2);
                }
            }
            calcBackgroundColor(wallpaper, 1);
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.actionbar.-$$Lambda$Theme$fkwFafwB3HY0wiT6nDFj0eXACUE
                @Override // java.lang.Runnable
                public final void run() {
                    Theme.lambda$null$6();
                }
            });
        }
    }

    static /* synthetic */ void lambda$null$6() {
        applyChatServiceMessageColor();
        NotificationCenter.getGlobalInstance().postNotificationName(NotificationCenter.didSetNewWallpapper, new Object[0]);
    }

    public static Drawable getThemedWallpaper(boolean thumb) {
        Integer backgroundColor = currentColors.get(key_chat_wallpaper);
        if (backgroundColor != null) {
            Integer gradientToColor = currentColors.get(key_chat_wallpaper_gradient_to);
            return gradientToColor == null ? new ColorDrawable(backgroundColor.intValue()) : new BackgroundGradientDrawable(GradientDrawable.Orientation.BL_TR, new int[]{backgroundColor.intValue(), gradientToColor.intValue()});
        }
        if (themedWallpaperFileOffset > 0 && (currentTheme.pathToFile != null || currentTheme.assetName != null)) {
            FileInputStream stream = null;
            try {
                try {
                    File file = currentTheme.assetName != null ? getAssetFile(currentTheme.assetName) : new File(currentTheme.pathToFile);
                    stream = new FileInputStream(file);
                    stream.getChannel().position(themedWallpaperFileOffset);
                    BitmapFactory.Options opts = new BitmapFactory.Options();
                    int scaleFactor = 1;
                    if (thumb) {
                        opts.inJustDecodeBounds = true;
                        float photoW = opts.outWidth;
                        float photoH = opts.outHeight;
                        int maxWidth = AndroidUtilities.dp(100.0f);
                        while (true) {
                            if (photoW <= maxWidth && photoH <= maxWidth) {
                                break;
                            }
                            scaleFactor *= 2;
                            photoW /= 2.0f;
                            photoH /= 2.0f;
                        }
                    }
                    opts.inJustDecodeBounds = false;
                    opts.inSampleSize = scaleFactor;
                    Bitmap bitmap = BitmapFactory.decodeStream(stream, null, opts);
                    if (bitmap != null) {
                        BitmapDrawable bitmapDrawable = new BitmapDrawable(bitmap);
                        try {
                            stream.close();
                        } catch (Exception e) {
                            FileLog.e(e);
                        }
                        return bitmapDrawable;
                    }
                    stream.close();
                } catch (Throwable e2) {
                    try {
                        FileLog.e(e2);
                        if (stream != null) {
                            stream.close();
                        }
                    } catch (Throwable th) {
                        if (stream != null) {
                            try {
                                stream.close();
                            } catch (Exception e3) {
                                FileLog.e(e3);
                            }
                        }
                        throw th;
                    }
                }
            } catch (Exception e4) {
                FileLog.e(e4);
            }
        }
        return null;
    }

    public static long getSelectedBackgroundId() {
        SharedPreferences preferences = MessagesController.getGlobalMainSettings();
        int background = preferences.getInt("selectedBackground", 1000001);
        if (background != DEFAULT_BACKGROUND_ID) {
            preferences.edit().putLong("selectedBackground2", background).remove("selectedBackground").commit();
        }
        long id = preferences.getLong("selectedBackground2", DEFAULT_BACKGROUND_ID);
        if (!hasWallpaperFromTheme() || preferences.getBoolean("overrideThemeWallpaper", false)) {
            return id == -2 ? DEFAULT_BACKGROUND_ID : id;
        }
        if (TextUtils.isEmpty(themedWallpaperLink)) {
            return -2L;
        }
        return id;
    }

    public static Drawable getCachedWallpaper() {
        synchronized (wallpaperSync) {
            if (themedWallpaper != null) {
                return themedWallpaper;
            }
            return wallpaper;
        }
    }

    public static Drawable getCachedWallpaperNonBlocking() {
        Drawable drawable = themedWallpaper;
        if (drawable != null) {
            return drawable;
        }
        return wallpaper;
    }

    public static boolean isWallpaperMotion() {
        return isWallpaperMotion;
    }

    public static boolean isPatternWallpaper() {
        return isPatternWallpaper;
    }
}
