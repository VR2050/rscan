package im.uwrkaxlmjj.ui;

import android.animation.Animator;
import android.animation.AnimatorListenerAdapter;
import android.animation.AnimatorSet;
import android.animation.ObjectAnimator;
import android.app.Dialog;
import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.PackageInfo;
import android.graphics.Bitmap;
import android.graphics.Canvas;
import android.graphics.Paint;
import android.graphics.PorterDuff;
import android.graphics.PorterDuffColorFilter;
import android.graphics.Rect;
import android.graphics.Typeface;
import android.graphics.drawable.Drawable;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.Vibrator;
import android.text.Editable;
import android.text.SpannableStringBuilder;
import android.text.TextPaint;
import android.text.TextUtils;
import android.text.TextWatcher;
import android.text.method.PasswordTransformationMethod;
import android.text.style.ClickableSpan;
import android.text.style.ForegroundColorSpan;
import android.util.Base64;
import android.util.Property;
import android.view.ActionMode;
import android.view.KeyEvent;
import android.view.Menu;
import android.view.MenuItem;
import android.view.MotionEvent;
import android.view.View;
import android.view.ViewGroup;
import android.view.animation.AccelerateDecelerateInterpolator;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import androidx.core.content.FileProvider;
import com.google.android.exoplayer2.extractor.ts.TsExtractor;
import com.google.firebase.remoteconfig.RemoteConfigConstants;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.ApplicationLoader;
import im.uwrkaxlmjj.messenger.BuildVars;
import im.uwrkaxlmjj.messenger.DispatchQueue;
import im.uwrkaxlmjj.messenger.DownloadController;
import im.uwrkaxlmjj.messenger.FileLoader;
import im.uwrkaxlmjj.messenger.FileLog;
import im.uwrkaxlmjj.messenger.ImageLoader;
import im.uwrkaxlmjj.messenger.ImageLocation;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.messenger.MediaController;
import im.uwrkaxlmjj.messenger.MessageObject;
import im.uwrkaxlmjj.messenger.MrzRecognizer;
import im.uwrkaxlmjj.messenger.NotificationCenter;
import im.uwrkaxlmjj.messenger.SRPHelper;
import im.uwrkaxlmjj.messenger.SecureDocument;
import im.uwrkaxlmjj.messenger.SecureDocumentKey;
import im.uwrkaxlmjj.messenger.SendMessagesHelper;
import im.uwrkaxlmjj.messenger.SharedConfig;
import im.uwrkaxlmjj.messenger.UserConfig;
import im.uwrkaxlmjj.messenger.UserObject;
import im.uwrkaxlmjj.messenger.Utilities;
import im.uwrkaxlmjj.messenger.browser.Browser;
import im.uwrkaxlmjj.phoneformat.PhoneFormat;
import im.uwrkaxlmjj.tgnet.ConnectionsManager;
import im.uwrkaxlmjj.tgnet.RequestDelegate;
import im.uwrkaxlmjj.tgnet.TLObject;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.ui.CountrySelectActivity;
import im.uwrkaxlmjj.ui.DocumentSelectActivity;
import im.uwrkaxlmjj.ui.MrzCameraActivity;
import im.uwrkaxlmjj.ui.PassportActivity;
import im.uwrkaxlmjj.ui.PhotoAlbumPickerActivity;
import im.uwrkaxlmjj.ui.PhotoViewer;
import im.uwrkaxlmjj.ui.actionbar.ActionBar;
import im.uwrkaxlmjj.ui.actionbar.ActionBarMenu;
import im.uwrkaxlmjj.ui.actionbar.ActionBarMenuItem;
import im.uwrkaxlmjj.ui.actionbar.AlertDialog;
import im.uwrkaxlmjj.ui.actionbar.BaseFragment;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.actionbar.ThemeDescription;
import im.uwrkaxlmjj.ui.cells.CheckBoxCell;
import im.uwrkaxlmjj.ui.cells.HeaderCell;
import im.uwrkaxlmjj.ui.cells.ShadowSectionCell;
import im.uwrkaxlmjj.ui.cells.TextDetailSettingsCell;
import im.uwrkaxlmjj.ui.cells.TextInfoPrivacyCell;
import im.uwrkaxlmjj.ui.cells.TextSettingsCell;
import im.uwrkaxlmjj.ui.components.AlertsCreator;
import im.uwrkaxlmjj.ui.components.AvatarDrawable;
import im.uwrkaxlmjj.ui.components.BackupImageView;
import im.uwrkaxlmjj.ui.components.ChatAttachAlert;
import im.uwrkaxlmjj.ui.components.ContextProgressView;
import im.uwrkaxlmjj.ui.components.EditTextBoldCursor;
import im.uwrkaxlmjj.ui.components.EmptyTextProgressView;
import im.uwrkaxlmjj.ui.components.LayoutHelper;
import im.uwrkaxlmjj.ui.components.RadialProgress;
import im.uwrkaxlmjj.ui.components.SlideView;
import im.uwrkaxlmjj.ui.components.URLSpanNoUnderline;
import im.uwrkaxlmjj.ui.components.toast.ToastUtils;
import im.uwrkaxlmjj.ui.hui.visualcall.PermissionUtils;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.RandomAccessFile;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Timer;
import java.util.TimerTask;
import kotlin.UByte;
import kotlin.text.Typography;
import mpEIGo.juqQQs.esbSDO.R;
import org.json.JSONObject;
import org.slf4j.Marker;

/* JADX INFO: loaded from: classes5.dex */
public class PassportActivity extends BaseFragment implements NotificationCenter.NotificationCenterDelegate {
    private static final int FIELD_ADDRESS_COUNT = 6;
    private static final int FIELD_BIRTHDAY = 3;
    private static final int FIELD_CARDNUMBER = 7;
    private static final int FIELD_CITIZENSHIP = 5;
    private static final int FIELD_CITY = 3;
    private static final int FIELD_COUNTRY = 5;
    private static final int FIELD_EMAIL = 0;
    private static final int FIELD_EXPIRE = 8;
    private static final int FIELD_GENDER = 4;
    private static final int FIELD_IDENTITY_COUNT = 9;
    private static final int FIELD_IDENTITY_NODOC_COUNT = 7;
    private static final int FIELD_MIDNAME = 1;
    private static final int FIELD_NAME = 0;
    private static final int FIELD_NATIVE_COUNT = 3;
    private static final int FIELD_NATIVE_MIDNAME = 1;
    private static final int FIELD_NATIVE_NAME = 0;
    private static final int FIELD_NATIVE_SURNAME = 2;
    private static final int FIELD_PASSWORD = 0;
    private static final int FIELD_PHONE = 2;
    private static final int FIELD_PHONECODE = 1;
    private static final int FIELD_PHONECOUNTRY = 0;
    private static final int FIELD_POSTCODE = 2;
    private static final int FIELD_RESIDENCE = 6;
    private static final int FIELD_STATE = 4;
    private static final int FIELD_STREET1 = 0;
    private static final int FIELD_STREET2 = 1;
    private static final int FIELD_SURNAME = 2;
    public static final int TYPE_ADDRESS = 2;
    public static final int TYPE_EMAIL = 4;
    public static final int TYPE_EMAIL_VERIFICATION = 6;
    public static final int TYPE_IDENTITY = 1;
    public static final int TYPE_MANAGE = 8;
    public static final int TYPE_PASSWORD = 5;
    public static final int TYPE_PHONE = 3;
    public static final int TYPE_PHONE_VERIFICATION = 7;
    public static final int TYPE_REQUEST = 0;
    private static final int UPLOADING_TYPE_DOCUMENTS = 0;
    private static final int UPLOADING_TYPE_FRONT = 2;
    private static final int UPLOADING_TYPE_REVERSE = 3;
    private static final int UPLOADING_TYPE_SELFIE = 1;
    private static final int UPLOADING_TYPE_TRANSLATION = 4;
    private static final int attach_document = 4;
    private static final int attach_gallery = 1;
    private static final int attach_photo = 0;
    private static final int done_button = 2;
    private static final int info_item = 1;
    private TextView acceptTextView;
    private TextSettingsCell addDocumentCell;
    private ShadowSectionCell addDocumentSectionCell;
    private boolean allowNonLatinName;
    private ArrayList<TLRPC.TL_secureRequiredType> availableDocumentTypes;
    private TextInfoPrivacyCell bottomCell;
    private TextInfoPrivacyCell bottomCellTranslation;
    private FrameLayout bottomLayout;
    private boolean callbackCalled;
    private ChatAttachAlert chatAttachAlert;
    private HashMap<String, String> codesMap;
    private ArrayList<String> countriesArray;
    private HashMap<String, String> countriesMap;
    private int currentActivityType;
    private int currentBotId;
    private String currentCallbackUrl;
    private String currentCitizeship;
    private HashMap<String, String> currentDocumentValues;
    private TLRPC.TL_secureRequiredType currentDocumentsType;
    private TLRPC.TL_secureValue currentDocumentsTypeValue;
    private String currentEmail;
    private int[] currentExpireDate;
    private TLRPC.TL_account_authorizationForm currentForm;
    private String currentGender;
    private String currentNonce;
    private TLRPC.TL_account_password currentPassword;
    private String currentPayload;
    private TLRPC.TL_auth_sentCode currentPhoneVerification;
    private LinearLayout currentPhotoViewerLayout;
    private String currentPicturePath;
    private String currentPublicKey;
    private String currentResidence;
    private String currentScope;
    private TLRPC.TL_secureRequiredType currentType;
    private TLRPC.TL_secureValue currentTypeValue;
    private HashMap<String, String> currentValues;
    private int currentViewNum;
    private PassportActivityDelegate delegate;
    private TextSettingsCell deletePassportCell;
    private ArrayList<View> dividers;
    private boolean documentOnly;
    private ArrayList<SecureDocument> documents;
    private HashMap<SecureDocument, SecureDocumentCell> documentsCells;
    private HashMap<String, String> documentsErrors;
    private LinearLayout documentsLayout;
    private HashMap<TLRPC.TL_secureRequiredType, TLRPC.TL_secureRequiredType> documentsToTypesLink;
    private ActionBarMenuItem doneItem;
    private AnimatorSet doneItemAnimation;
    private int emailCodeLength;
    private ImageView emptyImageView;
    private LinearLayout emptyLayout;
    private TextView emptyTextView1;
    private TextView emptyTextView2;
    private TextView emptyTextView3;
    private EmptyTextProgressView emptyView;
    private HashMap<String, HashMap<String, String>> errorsMap;
    private HashMap<String, String> errorsValues;
    private View extraBackgroundView;
    private View extraBackgroundView2;
    private HashMap<String, String> fieldsErrors;
    private SecureDocument frontDocument;
    private LinearLayout frontLayout;
    private HeaderCell headerCell;
    private boolean ignoreOnFailure;
    private boolean ignoreOnPhoneChange;
    private boolean ignoreOnTextChange;
    private String initialValues;
    private EditTextBoldCursor[] inputExtraFields;
    private ViewGroup[] inputFieldContainers;
    private EditTextBoldCursor[] inputFields;
    private HashMap<String, String> languageMap;
    private LinearLayout linearLayout2;
    private HashMap<String, String> mainErrorsMap;
    private TextInfoPrivacyCell nativeInfoCell;
    private boolean needActivityResult;
    private CharSequence noAllDocumentsErrorText;
    private CharSequence noAllTranslationErrorText;
    private ImageView noPasswordImageView;
    private TextView noPasswordSetTextView;
    private TextView noPasswordTextView;
    private boolean[] nonLatinNames;
    private FrameLayout passwordAvatarContainer;
    private TextView passwordForgotButton;
    private TextInfoPrivacyCell passwordInfoRequestTextView;
    private TextInfoPrivacyCell passwordRequestTextView;
    private PassportActivityDelegate pendingDelegate;
    private ErrorRunnable pendingErrorRunnable;
    private Runnable pendingFinishRunnable;
    private String pendingPhone;
    private Dialog permissionsDialog;
    private ArrayList<String> permissionsItems;
    private HashMap<String, String> phoneFormatMap;
    private TextView plusTextView;
    private PassportActivity presentAfterAnimation;
    private AlertDialog progressDialog;
    private ContextProgressView progressView;
    private ContextProgressView progressViewButton;
    private PhotoViewer.PhotoViewerProvider provider;
    private SecureDocument reverseDocument;
    private LinearLayout reverseLayout;
    private byte[] saltedPassword;
    private byte[] savedPasswordHash;
    private byte[] savedSaltedPassword;
    private TextSettingsCell scanDocumentCell;
    private int scrollHeight;
    private ScrollView scrollView;
    private ShadowSectionCell sectionCell;
    private ShadowSectionCell sectionCell2;
    private byte[] secureSecret;
    private long secureSecretId;
    private SecureDocument selfieDocument;
    private LinearLayout selfieLayout;
    private TextInfoPrivacyCell topErrorCell;
    private ArrayList<SecureDocument> translationDocuments;
    private LinearLayout translationLayout;
    private HashMap<TLRPC.TL_secureRequiredType, HashMap<String, String>> typesValues;
    private HashMap<TLRPC.TL_secureRequiredType, TextDetailSecureCell> typesViews;
    private TextSettingsCell uploadDocumentCell;
    private TextDetailSettingsCell uploadFrontCell;
    private TextDetailSettingsCell uploadReverseCell;
    private TextDetailSettingsCell uploadSelfieCell;
    private TextSettingsCell uploadTranslationCell;
    private HashMap<String, SecureDocument> uploadingDocuments;
    private int uploadingFileType;
    private boolean useCurrentValue;
    private int usingSavedPassword;
    private SlideView[] views;

    /* JADX INFO: Access modifiers changed from: private */
    interface ErrorRunnable {
        void onError(String str, String str2);
    }

    /* JADX INFO: Access modifiers changed from: private */
    interface PassportActivityDelegate {
        void deleteValue(TLRPC.TL_secureRequiredType tL_secureRequiredType, TLRPC.TL_secureRequiredType tL_secureRequiredType2, ArrayList<TLRPC.TL_secureRequiredType> arrayList, boolean z, Runnable runnable, ErrorRunnable errorRunnable);

        SecureDocument saveFile(TLRPC.TL_secureFile tL_secureFile);

        void saveValue(TLRPC.TL_secureRequiredType tL_secureRequiredType, String str, String str2, TLRPC.TL_secureRequiredType tL_secureRequiredType2, String str3, ArrayList<SecureDocument> arrayList, SecureDocument secureDocument, ArrayList<SecureDocument> arrayList2, SecureDocument secureDocument2, SecureDocument secureDocument3, Runnable runnable, ErrorRunnable errorRunnable);
    }

    public class LinkSpan extends ClickableSpan {
        public LinkSpan() {
        }

        @Override // android.text.style.ClickableSpan, android.text.style.CharacterStyle
        public void updateDrawState(TextPaint ds) {
            super.updateDrawState(ds);
            ds.setUnderlineText(true);
            ds.setTypeface(AndroidUtilities.getTypeface("fonts/rmedium.ttf"));
        }

        @Override // android.text.style.ClickableSpan
        public void onClick(View widget) {
            Browser.openUrl(PassportActivity.this.getParentActivity(), PassportActivity.this.currentForm.privacy_policy_url);
        }
    }

    public class TextDetailSecureCell extends FrameLayout {
        private ImageView checkImageView;
        private boolean needDivider;
        private TextView textView;
        private TextView valueTextView;

        public TextDetailSecureCell(Context context) {
            super(context);
            int padding = PassportActivity.this.currentActivityType == 8 ? 21 : 51;
            TextView textView = new TextView(context);
            this.textView = textView;
            textView.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteBlackText));
            this.textView.setTextSize(1, 16.0f);
            this.textView.setLines(1);
            this.textView.setMaxLines(1);
            this.textView.setSingleLine(true);
            this.textView.setEllipsize(TextUtils.TruncateAt.END);
            this.textView.setGravity((LocaleController.isRTL ? 5 : 3) | 16);
            addView(this.textView, LayoutHelper.createFrame(-2.0f, -2.0f, (LocaleController.isRTL ? 5 : 3) | 48, LocaleController.isRTL ? padding : 21, 10.0f, LocaleController.isRTL ? 21 : padding, 0.0f));
            TextView textView2 = new TextView(context);
            this.valueTextView = textView2;
            textView2.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteGrayText2));
            this.valueTextView.setTextSize(1, 13.0f);
            this.valueTextView.setGravity(LocaleController.isRTL ? 5 : 3);
            this.valueTextView.setLines(1);
            this.valueTextView.setMaxLines(1);
            this.valueTextView.setSingleLine(true);
            this.valueTextView.setEllipsize(TextUtils.TruncateAt.END);
            this.valueTextView.setPadding(0, 0, 0, 0);
            addView(this.valueTextView, LayoutHelper.createFrame(-2.0f, -2.0f, (LocaleController.isRTL ? 5 : 3) | 48, LocaleController.isRTL ? padding : 21, 35.0f, LocaleController.isRTL ? 21 : padding, 0.0f));
            ImageView imageView = new ImageView(context);
            this.checkImageView = imageView;
            imageView.setColorFilter(new PorterDuffColorFilter(Theme.getColor(Theme.key_featuredStickers_addedIcon), PorterDuff.Mode.SRC_IN));
            this.checkImageView.setImageResource(R.id.ic_selected);
            addView(this.checkImageView, LayoutHelper.createFrame(-2.0f, -2.0f, (LocaleController.isRTL ? 3 : 5) | 48, 21.0f, 25.0f, 21.0f, 0.0f));
        }

        @Override // android.widget.FrameLayout, android.view.View
        protected void onMeasure(int i, int i2) {
            super.onMeasure(View.MeasureSpec.makeMeasureSpec(View.MeasureSpec.getSize(i), 1073741824), View.MeasureSpec.makeMeasureSpec(AndroidUtilities.dp(64.0f) + (this.needDivider ? 1 : 0), 1073741824));
        }

        public void setTextAndValue(String text, CharSequence value, boolean divider) {
            this.textView.setText(text);
            this.valueTextView.setText(value);
            this.needDivider = divider;
            setWillNotDraw(!divider);
        }

        public void setChecked(boolean checked) {
            this.checkImageView.setVisibility(checked ? 0 : 4);
        }

        public void setValue(CharSequence value) {
            this.valueTextView.setText(value);
        }

        public void setNeedDivider(boolean value) {
            this.needDivider = value;
            setWillNotDraw(!value);
            invalidate();
        }

        @Override // android.view.View
        protected void onDraw(Canvas canvas) {
            if (this.needDivider) {
                canvas.drawLine(LocaleController.isRTL ? 0.0f : AndroidUtilities.dp(20.0f), getMeasuredHeight() - 1, getMeasuredWidth() - (LocaleController.isRTL ? AndroidUtilities.dp(20.0f) : 0), getMeasuredHeight() - 1, Theme.dividerPaint);
            }
        }
    }

    public class SecureDocumentCell extends FrameLayout implements DownloadController.FileDownloadProgressListener {
        private int TAG;
        private int buttonState;
        private SecureDocument currentSecureDocument;
        private BackupImageView imageView;
        private RadialProgress radialProgress;
        private TextView textView;
        private TextView valueTextView;

        public SecureDocumentCell(Context context) {
            super(context);
            this.TAG = DownloadController.getInstance(PassportActivity.this.currentAccount).generateObserverTag();
            this.radialProgress = new RadialProgress(this);
            BackupImageView backupImageView = new BackupImageView(context);
            this.imageView = backupImageView;
            addView(backupImageView, LayoutHelper.createFrame(48.0f, 48.0f, (LocaleController.isRTL ? 5 : 3) | 48, 21.0f, 8.0f, 21.0f, 0.0f));
            TextView textView = new TextView(context);
            this.textView = textView;
            textView.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteBlackText));
            this.textView.setTextSize(1, 16.0f);
            this.textView.setLines(1);
            this.textView.setMaxLines(1);
            this.textView.setSingleLine(true);
            this.textView.setEllipsize(TextUtils.TruncateAt.END);
            this.textView.setGravity((LocaleController.isRTL ? 5 : 3) | 16);
            addView(this.textView, LayoutHelper.createFrame(-2.0f, -2.0f, (LocaleController.isRTL ? 5 : 3) | 48, LocaleController.isRTL ? 21 : 81, 10.0f, LocaleController.isRTL ? 81 : 21, 0.0f));
            TextView textView2 = new TextView(context);
            this.valueTextView = textView2;
            textView2.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteGrayText2));
            this.valueTextView.setTextSize(1, 13.0f);
            this.valueTextView.setGravity(LocaleController.isRTL ? 5 : 3);
            this.valueTextView.setLines(1);
            this.valueTextView.setMaxLines(1);
            this.valueTextView.setSingleLine(true);
            this.valueTextView.setPadding(0, 0, 0, 0);
            addView(this.valueTextView, LayoutHelper.createFrame(-2.0f, -2.0f, (LocaleController.isRTL ? 5 : 3) | 48, LocaleController.isRTL ? 21 : 81, 35.0f, LocaleController.isRTL ? 81 : 21, 0.0f));
            setWillNotDraw(false);
        }

        @Override // android.widget.FrameLayout, android.view.View
        protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
            super.onMeasure(View.MeasureSpec.makeMeasureSpec(View.MeasureSpec.getSize(widthMeasureSpec), 1073741824), View.MeasureSpec.makeMeasureSpec(AndroidUtilities.dp(64.0f) + 1, 1073741824));
        }

        @Override // android.widget.FrameLayout, android.view.ViewGroup, android.view.View
        protected void onLayout(boolean changed, int left, int top, int right, int bottom) {
            super.onLayout(changed, left, top, right, bottom);
            int x = this.imageView.getLeft() + ((this.imageView.getMeasuredWidth() - AndroidUtilities.dp(24.0f)) / 2);
            int y = this.imageView.getTop() + ((this.imageView.getMeasuredHeight() - AndroidUtilities.dp(24.0f)) / 2);
            this.radialProgress.setProgressRect(x, y, AndroidUtilities.dp(24.0f) + x, AndroidUtilities.dp(24.0f) + y);
        }

        @Override // android.view.ViewGroup
        protected boolean drawChild(Canvas canvas, View child, long drawingTime) {
            boolean result = super.drawChild(canvas, child, drawingTime);
            if (child == this.imageView) {
                this.radialProgress.draw(canvas);
            }
            return result;
        }

        public void setTextAndValueAndImage(String text, CharSequence value, SecureDocument document) {
            this.textView.setText(text);
            this.valueTextView.setText(value);
            this.imageView.setImage(document, "48_48");
            this.currentSecureDocument = document;
            updateButtonState(false);
        }

        public void setValue(CharSequence value) {
            this.valueTextView.setText(value);
        }

        public void updateButtonState(boolean animated) {
            String fileName = FileLoader.getAttachFileName(this.currentSecureDocument);
            File path = FileLoader.getPathToAttach(this.currentSecureDocument);
            boolean fileExists = path.exists();
            if (TextUtils.isEmpty(fileName)) {
                this.radialProgress.setBackground(null, false, false);
                return;
            }
            if (this.currentSecureDocument.path != null) {
                if (this.currentSecureDocument.inputFile != null) {
                    DownloadController.getInstance(PassportActivity.this.currentAccount).removeLoadingFileObserver(this);
                    this.radialProgress.setBackground(null, false, animated);
                    this.buttonState = -1;
                    return;
                } else {
                    DownloadController.getInstance(PassportActivity.this.currentAccount).addLoadingFileObserver(this.currentSecureDocument.path, this);
                    this.buttonState = 1;
                    Float progress = ImageLoader.getInstance().getFileProgress(this.currentSecureDocument.path);
                    this.radialProgress.setBackground(Theme.chat_photoStatesDrawables[5][0], true, animated);
                    this.radialProgress.setProgress(progress != null ? progress.floatValue() : 0.0f, false);
                    invalidate();
                    return;
                }
            }
            if (fileExists) {
                DownloadController.getInstance(PassportActivity.this.currentAccount).removeLoadingFileObserver(this);
                this.buttonState = -1;
                this.radialProgress.setBackground(null, false, animated);
                invalidate();
                return;
            }
            DownloadController.getInstance(PassportActivity.this.currentAccount).addLoadingFileObserver(fileName, this);
            this.buttonState = 1;
            Float progress2 = ImageLoader.getInstance().getFileProgress(fileName);
            this.radialProgress.setBackground(Theme.chat_photoStatesDrawables[5][0], true, animated);
            this.radialProgress.setProgress(progress2 != null ? progress2.floatValue() : 0.0f, animated);
            invalidate();
        }

        @Override // android.view.View
        public void invalidate() {
            super.invalidate();
            this.textView.invalidate();
        }

        @Override // android.view.View
        protected void onDraw(Canvas canvas) {
            canvas.drawLine(LocaleController.isRTL ? 0.0f : AndroidUtilities.dp(20.0f), getMeasuredHeight() - 1, getMeasuredWidth() - (LocaleController.isRTL ? AndroidUtilities.dp(20.0f) : 0), getMeasuredHeight() - 1, Theme.dividerPaint);
        }

        @Override // im.uwrkaxlmjj.messenger.DownloadController.FileDownloadProgressListener
        public void onFailedDownload(String fileName, boolean canceled) {
            updateButtonState(false);
        }

        @Override // im.uwrkaxlmjj.messenger.DownloadController.FileDownloadProgressListener
        public void onSuccessDownload(String fileName) {
            this.radialProgress.setProgress(1.0f, true);
            updateButtonState(true);
        }

        @Override // im.uwrkaxlmjj.messenger.DownloadController.FileDownloadProgressListener
        public void onProgressDownload(String fileName, float progress) {
            this.radialProgress.setProgress(progress, true);
            if (this.buttonState != 1) {
                updateButtonState(false);
            }
        }

        @Override // im.uwrkaxlmjj.messenger.DownloadController.FileDownloadProgressListener
        public void onProgressUpload(String fileName, float progress, boolean isEncrypted) {
            this.radialProgress.setProgress(progress, true);
        }

        @Override // im.uwrkaxlmjj.messenger.DownloadController.FileDownloadProgressListener
        public int getObserverTag() {
            return this.TAG;
        }
    }

    /* JADX WARN: 'this' call moved to the top of the method (can break code semantics) */
    /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
    /* JADX WARN: Removed duplicated region for block: B:58:0x01ce  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public PassportActivity(int r23, int r24, java.lang.String r25, java.lang.String r26, java.lang.String r27, java.lang.String r28, java.lang.String r29, im.uwrkaxlmjj.tgnet.TLRPC.TL_account_authorizationForm r30, im.uwrkaxlmjj.tgnet.TLRPC.TL_account_password r31) {
        /*
            Method dump skipped, instruction units count: 722
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.ui.PassportActivity.<init>(int, int, java.lang.String, java.lang.String, java.lang.String, java.lang.String, java.lang.String, im.uwrkaxlmjj.tgnet.TLRPC$TL_account_authorizationForm, im.uwrkaxlmjj.tgnet.TLRPC$TL_account_password):void");
    }

    public PassportActivity(int type, TLRPC.TL_account_authorizationForm form, TLRPC.TL_account_password accountPassword, TLRPC.TL_secureRequiredType secureType, TLRPC.TL_secureValue secureValue, TLRPC.TL_secureRequiredType secureDocumentsType, TLRPC.TL_secureValue secureDocumentsValue, HashMap<String, String> values, HashMap<String, String> documentValues) {
        this.currentCitizeship = "";
        this.currentResidence = "";
        this.currentExpireDate = new int[3];
        this.dividers = new ArrayList<>();
        this.nonLatinNames = new boolean[3];
        this.allowNonLatinName = true;
        this.countriesArray = new ArrayList<>();
        this.countriesMap = new HashMap<>();
        this.codesMap = new HashMap<>();
        this.phoneFormatMap = new HashMap<>();
        this.documents = new ArrayList<>();
        this.translationDocuments = new ArrayList<>();
        this.documentsCells = new HashMap<>();
        this.uploadingDocuments = new HashMap<>();
        this.typesValues = new HashMap<>();
        this.typesViews = new HashMap<>();
        this.documentsToTypesLink = new HashMap<>();
        this.errorsMap = new HashMap<>();
        this.mainErrorsMap = new HashMap<>();
        this.errorsValues = new HashMap<>();
        this.provider = new PhotoViewer.EmptyPhotoViewerProvider() { // from class: im.uwrkaxlmjj.ui.PassportActivity.1
            @Override // im.uwrkaxlmjj.ui.PhotoViewer.EmptyPhotoViewerProvider, im.uwrkaxlmjj.ui.PhotoViewer.PhotoViewerProvider
            public PhotoViewer.PlaceProviderObject getPlaceForPhoto(MessageObject messageObject, TLRPC.FileLocation fileLocation, int index, boolean needPreview) {
                if (index >= 0 && index < PassportActivity.this.currentPhotoViewerLayout.getChildCount()) {
                    SecureDocumentCell cell = (SecureDocumentCell) PassportActivity.this.currentPhotoViewerLayout.getChildAt(index);
                    int[] coords = new int[2];
                    cell.imageView.getLocationInWindow(coords);
                    PhotoViewer.PlaceProviderObject object = new PhotoViewer.PlaceProviderObject();
                    object.viewX = coords[0];
                    object.viewY = coords[1] - (Build.VERSION.SDK_INT < 21 ? AndroidUtilities.statusBarHeight : 0);
                    object.parentView = PassportActivity.this.currentPhotoViewerLayout;
                    object.imageReceiver = cell.imageView.getImageReceiver();
                    object.thumb = object.imageReceiver.getBitmapSafe();
                    return object;
                }
                return null;
            }

            @Override // im.uwrkaxlmjj.ui.PhotoViewer.EmptyPhotoViewerProvider, im.uwrkaxlmjj.ui.PhotoViewer.PhotoViewerProvider
            public void deleteImageAtIndex(int index) {
                SecureDocument document = PassportActivity.this.uploadingFileType == 1 ? PassportActivity.this.selfieDocument : PassportActivity.this.uploadingFileType == 4 ? (SecureDocument) PassportActivity.this.translationDocuments.get(index) : PassportActivity.this.uploadingFileType == 2 ? PassportActivity.this.frontDocument : PassportActivity.this.uploadingFileType == 3 ? PassportActivity.this.reverseDocument : (SecureDocument) PassportActivity.this.documents.get(index);
                SecureDocumentCell cell = (SecureDocumentCell) PassportActivity.this.documentsCells.remove(document);
                if (cell == null) {
                    return;
                }
                String key = null;
                String hash = PassportActivity.this.getDocumentHash(document);
                if (PassportActivity.this.uploadingFileType == 1) {
                    PassportActivity.this.selfieDocument = null;
                    key = "selfie" + hash;
                } else if (PassportActivity.this.uploadingFileType != 4) {
                    if (PassportActivity.this.uploadingFileType == 2) {
                        PassportActivity.this.frontDocument = null;
                        key = "front" + hash;
                    } else if (PassportActivity.this.uploadingFileType == 3) {
                        PassportActivity.this.reverseDocument = null;
                        key = "reverse" + hash;
                    } else if (PassportActivity.this.uploadingFileType == 0) {
                        key = "files" + hash;
                    }
                } else {
                    key = "translation" + hash;
                }
                if (key != null) {
                    if (PassportActivity.this.documentsErrors != null) {
                        PassportActivity.this.documentsErrors.remove(key);
                    }
                    if (PassportActivity.this.errorsValues != null) {
                        PassportActivity.this.errorsValues.remove(key);
                    }
                }
                PassportActivity passportActivity = PassportActivity.this;
                passportActivity.updateUploadText(passportActivity.uploadingFileType);
                PassportActivity.this.currentPhotoViewerLayout.removeView(cell);
            }

            @Override // im.uwrkaxlmjj.ui.PhotoViewer.EmptyPhotoViewerProvider, im.uwrkaxlmjj.ui.PhotoViewer.PhotoViewerProvider
            public String getDeleteMessageString() {
                if (PassportActivity.this.uploadingFileType == 1) {
                    return LocaleController.formatString("PassportDeleteSelfieAlert", R.string.PassportDeleteSelfieAlert, new Object[0]);
                }
                return LocaleController.formatString("PassportDeleteScanAlert", R.string.PassportDeleteScanAlert, new Object[0]);
            }
        };
        this.currentActivityType = type;
        this.currentForm = form;
        this.currentType = secureType;
        if (secureType != null) {
            this.allowNonLatinName = secureType.native_names;
        }
        this.currentTypeValue = secureValue;
        this.currentDocumentsType = secureDocumentsType;
        this.currentDocumentsTypeValue = secureDocumentsValue;
        this.currentPassword = accountPassword;
        this.currentValues = values;
        this.currentDocumentValues = documentValues;
        int i = this.currentActivityType;
        if (i == 3) {
            this.permissionsItems = new ArrayList<>();
        } else if (i == 7) {
            this.views = new SlideView[3];
        }
        if (this.currentValues == null) {
            this.currentValues = new HashMap<>();
        }
        if (this.currentDocumentValues == null) {
            this.currentDocumentValues = new HashMap<>();
        }
        if (type == 5) {
            if (UserConfig.getInstance(this.currentAccount).savedPasswordHash != null && UserConfig.getInstance(this.currentAccount).savedSaltedPassword != null) {
                this.usingSavedPassword = 1;
                this.savedPasswordHash = UserConfig.getInstance(this.currentAccount).savedPasswordHash;
                this.savedSaltedPassword = UserConfig.getInstance(this.currentAccount).savedSaltedPassword;
            }
            TLRPC.TL_account_password tL_account_password = this.currentPassword;
            if (tL_account_password == null) {
                loadPasswordInfo();
            } else {
                TwoStepVerificationActivity.initPasswordNewAlgo(tL_account_password);
                if (this.usingSavedPassword == 1) {
                    onPasswordDone(true);
                }
            }
            if (!SharedConfig.isPassportConfigLoaded()) {
                TLRPC.TL_help_getPassportConfig req = new TLRPC.TL_help_getPassportConfig();
                req.hash = SharedConfig.passportConfigHash;
                ConnectionsManager.getInstance(this.currentAccount).sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PassportActivity$3IT4fuqfTxnv0jW8ZRFi5OB-aWI
                    @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                    public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PassportActivity$XlKdAIds69EmpXRpH-O_48B2c_8
                            @Override // java.lang.Runnable
                            public final void run() {
                                PassportActivity.lambda$null$0(tLObject);
                            }
                        });
                    }
                });
            }
        }
    }

    static /* synthetic */ void lambda$null$0(TLObject response) {
        if (response instanceof TLRPC.TL_help_passportConfig) {
            TLRPC.TL_help_passportConfig res = (TLRPC.TL_help_passportConfig) response;
            SharedConfig.setPassportConfig(res.countries_langs.data, res.hash);
        } else {
            SharedConfig.getCountryLangs();
        }
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onResume() {
        ViewGroup[] viewGroupArr;
        super.onResume();
        ChatAttachAlert chatAttachAlert = this.chatAttachAlert;
        if (chatAttachAlert != null) {
            chatAttachAlert.onResume();
        }
        if (this.currentActivityType == 5 && (viewGroupArr = this.inputFieldContainers) != null && viewGroupArr[0] != null && viewGroupArr[0].getVisibility() == 0) {
            this.inputFields[0].requestFocus();
            AndroidUtilities.showKeyboard(this.inputFields[0]);
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PassportActivity$qUSXG1GC2s8bobgYd4kHPLC6B8I
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$onResume$2$PassportActivity();
                }
            }, 200L);
        }
        AndroidUtilities.requestAdjustResize(getParentActivity(), this.classGuid);
    }

    public /* synthetic */ void lambda$onResume$2$PassportActivity() {
        ViewGroup[] viewGroupArr = this.inputFieldContainers;
        if (viewGroupArr != null && viewGroupArr[0] != null && viewGroupArr[0].getVisibility() == 0) {
            this.inputFields[0].requestFocus();
            AndroidUtilities.showKeyboard(this.inputFields[0]);
        }
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onPause() {
        super.onPause();
        ChatAttachAlert chatAttachAlert = this.chatAttachAlert;
        if (chatAttachAlert != null) {
            chatAttachAlert.onPause();
        }
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public boolean onFragmentCreate() {
        NotificationCenter.getInstance(this.currentAccount).addObserver(this, NotificationCenter.FileDidUpload);
        NotificationCenter.getInstance(this.currentAccount).addObserver(this, NotificationCenter.FileDidFailUpload);
        NotificationCenter.getInstance(this.currentAccount).addObserver(this, NotificationCenter.didSetTwoStepPassword);
        NotificationCenter.getInstance(this.currentAccount).addObserver(this, NotificationCenter.didRemoveTwoStepPassword);
        return super.onFragmentCreate();
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onFragmentDestroy() {
        super.onFragmentDestroy();
        NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.FileDidUpload);
        NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.FileDidFailUpload);
        NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.didSetTwoStepPassword);
        NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.didRemoveTwoStepPassword);
        callCallback(false);
        ChatAttachAlert chatAttachAlert = this.chatAttachAlert;
        if (chatAttachAlert != null) {
            chatAttachAlert.dismissInternal();
            this.chatAttachAlert.onDestroy();
        }
        if (this.currentActivityType == 7) {
            int a = 0;
            while (true) {
                SlideView[] slideViewArr = this.views;
                if (a >= slideViewArr.length) {
                    break;
                }
                if (slideViewArr[a] != null) {
                    slideViewArr[a].onDestroyActivity();
                }
                a++;
            }
            AlertDialog alertDialog = this.progressDialog;
            if (alertDialog != null) {
                try {
                    alertDialog.dismiss();
                } catch (Exception e) {
                    FileLog.e(e);
                }
                this.progressDialog = null;
            }
        }
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public View createView(Context context) {
        ChatAttachAlert chatAttachAlert;
        this.actionBar.setBackButtonImage(R.id.ic_back);
        this.actionBar.setAllowOverlayTitle(true);
        this.actionBar.setActionBarMenuOnItemClick(new AnonymousClass3());
        if (this.currentActivityType == 7) {
            ScrollView scrollView = new ScrollView(context) { // from class: im.uwrkaxlmjj.ui.PassportActivity.4
                @Override // android.widget.ScrollView, android.view.ViewGroup
                protected boolean onRequestFocusInDescendants(int direction, Rect previouslyFocusedRect) {
                    return false;
                }

                @Override // android.widget.ScrollView, android.view.ViewGroup, android.view.ViewParent
                public boolean requestChildRectangleOnScreen(View child, Rect rectangle, boolean immediate) {
                    if (PassportActivity.this.currentViewNum == 1 || PassportActivity.this.currentViewNum == 2 || PassportActivity.this.currentViewNum == 4) {
                        rectangle.bottom += AndroidUtilities.dp(40.0f);
                    }
                    return super.requestChildRectangleOnScreen(child, rectangle, immediate);
                }

                @Override // android.widget.ScrollView, android.widget.FrameLayout, android.view.View
                protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
                    PassportActivity.this.scrollHeight = View.MeasureSpec.getSize(heightMeasureSpec) - AndroidUtilities.dp(30.0f);
                    super.onMeasure(widthMeasureSpec, heightMeasureSpec);
                }
            };
            this.scrollView = scrollView;
            this.fragmentView = scrollView;
            this.scrollView.setFillViewport(true);
            AndroidUtilities.setScrollViewEdgeEffectColor(this.scrollView, Theme.getColor(Theme.key_actionBarDefault));
        } else {
            this.fragmentView = new FrameLayout(context);
            FrameLayout frameLayout = (FrameLayout) this.fragmentView;
            this.fragmentView.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundGray));
            ScrollView scrollView2 = new ScrollView(context) { // from class: im.uwrkaxlmjj.ui.PassportActivity.5
                @Override // android.widget.ScrollView, android.view.ViewGroup
                protected boolean onRequestFocusInDescendants(int direction, Rect previouslyFocusedRect) {
                    return false;
                }

                @Override // android.widget.ScrollView, android.view.ViewGroup, android.view.ViewParent
                public boolean requestChildRectangleOnScreen(View child, Rect rectangle, boolean immediate) {
                    rectangle.offset(child.getLeft() - child.getScrollX(), child.getTop() - child.getScrollY());
                    rectangle.top += AndroidUtilities.dp(20.0f);
                    rectangle.bottom += AndroidUtilities.dp(50.0f);
                    return super.requestChildRectangleOnScreen(child, rectangle, immediate);
                }
            };
            this.scrollView = scrollView2;
            scrollView2.setFillViewport(true);
            AndroidUtilities.setScrollViewEdgeEffectColor(this.scrollView, Theme.getColor(Theme.key_actionBarDefault));
            frameLayout.addView(this.scrollView, LayoutHelper.createFrame(-1.0f, -1.0f, 51, 0.0f, 0.0f, 0.0f, this.currentActivityType == 0 ? 48.0f : 0.0f));
            LinearLayout linearLayout = new LinearLayout(context);
            this.linearLayout2 = linearLayout;
            linearLayout.setOrientation(1);
            this.scrollView.addView(this.linearLayout2, new FrameLayout.LayoutParams(-1, -2));
        }
        int i = this.currentActivityType;
        if (i != 0 && i != 8) {
            ActionBarMenu menu = this.actionBar.createMenu();
            this.doneItem = menu.addItemWithWidth(2, R.drawable.ic_done, AndroidUtilities.dp(56.0f));
            ContextProgressView contextProgressView = new ContextProgressView(context, 1);
            this.progressView = contextProgressView;
            contextProgressView.setAlpha(0.0f);
            this.progressView.setScaleX(0.1f);
            this.progressView.setScaleY(0.1f);
            this.progressView.setVisibility(4);
            this.doneItem.addView(this.progressView, LayoutHelper.createFrame(-1, -1.0f));
            int i2 = this.currentActivityType;
            if ((i2 == 1 || i2 == 2) && (chatAttachAlert = this.chatAttachAlert) != null) {
                try {
                    if (chatAttachAlert.isShowing()) {
                        this.chatAttachAlert.dismiss();
                    }
                } catch (Exception e) {
                }
                this.chatAttachAlert.onDestroy();
                this.chatAttachAlert = null;
            }
        }
        int i3 = this.currentActivityType;
        if (i3 == 5) {
            createPasswordInterface(context);
        } else if (i3 == 0) {
            createRequestInterface(context);
        } else if (i3 == 1) {
            createIdentityInterface(context);
            fillInitialValues();
        } else if (i3 == 2) {
            createAddressInterface(context);
            fillInitialValues();
        } else if (i3 == 3) {
            createPhoneInterface(context);
        } else if (i3 == 4) {
            createEmailInterface(context);
        } else if (i3 == 6) {
            createEmailVerificationInterface(context);
        } else if (i3 == 7) {
            createPhoneVerificationInterface(context);
        } else if (i3 == 8) {
            createManageInterface(context);
        }
        return this.fragmentView;
    }

    /* JADX INFO: renamed from: im.uwrkaxlmjj.ui.PassportActivity$3, reason: invalid class name */
    class AnonymousClass3 extends ActionBar.ActionBarMenuOnItemClick {
        AnonymousClass3() {
        }

        private boolean onIdentityDone(final Runnable finishRunnable, final ErrorRunnable errorRunnable) {
            String string;
            String string2;
            String string3;
            char c = 0;
            if (PassportActivity.this.uploadingDocuments.isEmpty() && !PassportActivity.this.checkFieldsForError()) {
                int i = 3;
                char c2 = 2;
                char c3 = 1;
                if (PassportActivity.this.allowNonLatinName) {
                    PassportActivity.this.allowNonLatinName = false;
                    boolean error = false;
                    int a = 0;
                    while (a < PassportActivity.this.nonLatinNames.length) {
                        if (PassportActivity.this.nonLatinNames[a]) {
                            PassportActivity.this.inputFields[a].setErrorText(LocaleController.getString("PassportUseLatinOnly", R.string.PassportUseLatinOnly));
                            if (!error) {
                                error = true;
                                if (!PassportActivity.this.nonLatinNames[c]) {
                                    string = PassportActivity.this.inputFields[c].getText().toString();
                                } else {
                                    PassportActivity passportActivity = PassportActivity.this;
                                    string = passportActivity.getTranslitString(passportActivity.inputExtraFields[c].getText().toString());
                                }
                                final String firstName = string;
                                if (!PassportActivity.this.nonLatinNames[c3]) {
                                    string2 = PassportActivity.this.inputFields[c3].getText().toString();
                                } else {
                                    PassportActivity passportActivity2 = PassportActivity.this;
                                    string2 = passportActivity2.getTranslitString(passportActivity2.inputExtraFields[c3].getText().toString());
                                }
                                final String middleName = string2;
                                if (!PassportActivity.this.nonLatinNames[c2]) {
                                    string3 = PassportActivity.this.inputFields[c2].getText().toString();
                                } else {
                                    PassportActivity passportActivity3 = PassportActivity.this;
                                    string3 = passportActivity3.getTranslitString(passportActivity3.inputExtraFields[c2].getText().toString());
                                }
                                final String lastName = string3;
                                if (!TextUtils.isEmpty(firstName) && !TextUtils.isEmpty(middleName) && !TextUtils.isEmpty(lastName)) {
                                    final int num = a;
                                    AlertDialog.Builder builder = new AlertDialog.Builder(PassportActivity.this.getParentActivity());
                                    Object[] objArr = new Object[i];
                                    objArr[c] = firstName;
                                    objArr[c3] = middleName;
                                    objArr[c2] = lastName;
                                    builder.setMessage(LocaleController.formatString("PassportNameCheckAlert", R.string.PassportNameCheckAlert, objArr));
                                    builder.setTitle(LocaleController.getString("AppName", R.string.AppName));
                                    builder.setPositiveButton(LocaleController.getString("Done", R.string.Done), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PassportActivity$3$mHr7XPGDeKNbLV4ig6bW4-4DnUw
                                        @Override // android.content.DialogInterface.OnClickListener
                                        public final void onClick(DialogInterface dialogInterface, int i2) {
                                            this.f$0.lambda$onIdentityDone$0$PassportActivity$3(firstName, middleName, lastName, finishRunnable, errorRunnable, dialogInterface, i2);
                                        }
                                    });
                                    builder.setNegativeButton(LocaleController.getString("Edit", R.string.Edit), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PassportActivity$3$-y21tYoA9mlrhccuK3PLkhJ8xnI
                                        @Override // android.content.DialogInterface.OnClickListener
                                        public final void onClick(DialogInterface dialogInterface, int i2) {
                                            this.f$0.lambda$onIdentityDone$1$PassportActivity$3(num, dialogInterface, i2);
                                        }
                                    });
                                    PassportActivity.this.showDialog(builder.create());
                                } else {
                                    PassportActivity passportActivity4 = PassportActivity.this;
                                    passportActivity4.onFieldError(passportActivity4.inputFields[a]);
                                }
                            }
                        }
                        a++;
                        c = 0;
                        i = 3;
                        c2 = 2;
                        c3 = 1;
                    }
                    if (error) {
                        return false;
                    }
                }
                if (PassportActivity.this.isHasNotAnyChanges()) {
                    PassportActivity.this.finishFragment();
                    return false;
                }
                JSONObject json = null;
                JSONObject documentsJson = null;
                try {
                    if (!PassportActivity.this.documentOnly) {
                        HashMap<String, String> valuesToSave = new HashMap<>(PassportActivity.this.currentValues);
                        if (PassportActivity.this.currentType.native_names) {
                            if (PassportActivity.this.nativeInfoCell.getVisibility() == 0) {
                                valuesToSave.put("first_name_native", PassportActivity.this.inputExtraFields[0].getText().toString());
                                valuesToSave.put("middle_name_native", PassportActivity.this.inputExtraFields[1].getText().toString());
                                valuesToSave.put("last_name_native", PassportActivity.this.inputExtraFields[2].getText().toString());
                            } else {
                                valuesToSave.put("first_name_native", PassportActivity.this.inputFields[0].getText().toString());
                                valuesToSave.put("middle_name_native", PassportActivity.this.inputFields[1].getText().toString());
                                valuesToSave.put("last_name_native", PassportActivity.this.inputFields[2].getText().toString());
                            }
                        }
                        valuesToSave.put("first_name", PassportActivity.this.inputFields[0].getText().toString());
                        valuesToSave.put("middle_name", PassportActivity.this.inputFields[1].getText().toString());
                        valuesToSave.put("last_name", PassportActivity.this.inputFields[2].getText().toString());
                        valuesToSave.put("birth_date", PassportActivity.this.inputFields[3].getText().toString());
                        valuesToSave.put("gender", PassportActivity.this.currentGender);
                        valuesToSave.put("country_code", PassportActivity.this.currentCitizeship);
                        valuesToSave.put("residence_country_code", PassportActivity.this.currentResidence);
                        json = new JSONObject();
                        ArrayList<String> keys = new ArrayList<>(valuesToSave.keySet());
                        Collections.sort(keys, new Comparator() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PassportActivity$3$R1-NVvs5caKDG8haGL24sog2Lkc
                            @Override // java.util.Comparator
                            public final int compare(Object obj, Object obj2) {
                                return this.f$0.lambda$onIdentityDone$2$PassportActivity$3((String) obj, (String) obj2);
                            }
                        });
                        int size = keys.size();
                        for (int a2 = 0; a2 < size; a2++) {
                            String key = keys.get(a2);
                            json.put(key, valuesToSave.get(key));
                        }
                    }
                    if (PassportActivity.this.currentDocumentsType != null) {
                        HashMap<String, String> valuesToSave2 = new HashMap<>(PassportActivity.this.currentDocumentValues);
                        valuesToSave2.put("document_no", PassportActivity.this.inputFields[7].getText().toString());
                        if (PassportActivity.this.currentExpireDate[0] != 0) {
                            valuesToSave2.put("expiry_date", String.format(Locale.US, "%02d.%02d.%d", Integer.valueOf(PassportActivity.this.currentExpireDate[2]), Integer.valueOf(PassportActivity.this.currentExpireDate[1]), Integer.valueOf(PassportActivity.this.currentExpireDate[0])));
                        } else {
                            valuesToSave2.put("expiry_date", "");
                        }
                        documentsJson = new JSONObject();
                        ArrayList<String> keys2 = new ArrayList<>(valuesToSave2.keySet());
                        Collections.sort(keys2, new Comparator() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PassportActivity$3$e6ZUUwncbpq1aY0Tge9vxjGDA44
                            @Override // java.util.Comparator
                            public final int compare(Object obj, Object obj2) {
                                return this.f$0.lambda$onIdentityDone$3$PassportActivity$3((String) obj, (String) obj2);
                            }
                        });
                        int size2 = keys2.size();
                        for (int a3 = 0; a3 < size2; a3++) {
                            String key2 = keys2.get(a3);
                            documentsJson.put(key2, valuesToSave2.get(key2));
                        }
                    }
                } catch (Exception e) {
                }
                if (PassportActivity.this.fieldsErrors != null) {
                    PassportActivity.this.fieldsErrors.clear();
                }
                if (PassportActivity.this.documentsErrors != null) {
                    PassportActivity.this.documentsErrors.clear();
                }
                PassportActivityDelegate passportActivityDelegate = PassportActivity.this.delegate;
                TLRPC.TL_secureRequiredType tL_secureRequiredType = PassportActivity.this.currentType;
                SecureDocument secureDocument = null;
                String string4 = json != null ? json.toString() : null;
                TLRPC.TL_secureRequiredType tL_secureRequiredType2 = PassportActivity.this.currentDocumentsType;
                String string5 = documentsJson != null ? documentsJson.toString() : null;
                SecureDocument secureDocument2 = PassportActivity.this.selfieDocument;
                ArrayList<SecureDocument> arrayList = PassportActivity.this.translationDocuments;
                SecureDocument secureDocument3 = PassportActivity.this.frontDocument;
                if (PassportActivity.this.reverseLayout != null && PassportActivity.this.reverseLayout.getVisibility() == 0) {
                    secureDocument = PassportActivity.this.reverseDocument;
                }
                passportActivityDelegate.saveValue(tL_secureRequiredType, null, string4, tL_secureRequiredType2, string5, null, secureDocument2, arrayList, secureDocument3, secureDocument, finishRunnable, errorRunnable);
                return true;
            }
            return false;
        }

        public /* synthetic */ void lambda$onIdentityDone$0$PassportActivity$3(String firstName, String middleName, String lastName, Runnable finishRunnable, ErrorRunnable errorRunnable, DialogInterface dialogInterface, int i) {
            PassportActivity.this.inputFields[0].setText(firstName);
            PassportActivity.this.inputFields[1].setText(middleName);
            PassportActivity.this.inputFields[2].setText(lastName);
            PassportActivity.this.showEditDoneProgress(true, true);
            onIdentityDone(finishRunnable, errorRunnable);
        }

        public /* synthetic */ void lambda$onIdentityDone$1$PassportActivity$3(int num, DialogInterface dialogInterface, int i) {
            PassportActivity passportActivity = PassportActivity.this;
            passportActivity.onFieldError(passportActivity.inputFields[num]);
        }

        public /* synthetic */ int lambda$onIdentityDone$2$PassportActivity$3(String key1, String key2) {
            int val1 = PassportActivity.this.getFieldCost(key1);
            int val2 = PassportActivity.this.getFieldCost(key2);
            if (val1 < val2) {
                return -1;
            }
            if (val1 > val2) {
                return 1;
            }
            return 0;
        }

        public /* synthetic */ int lambda$onIdentityDone$3$PassportActivity$3(String key1, String key2) {
            int val1 = PassportActivity.this.getFieldCost(key1);
            int val2 = PassportActivity.this.getFieldCost(key2);
            if (val1 < val2) {
                return -1;
            }
            if (val1 > val2) {
                return 1;
            }
            return 0;
        }

        @Override // im.uwrkaxlmjj.ui.actionbar.ActionBar.ActionBarMenuOnItemClick
        public void onItemClick(int id) {
            JSONObject json;
            String value;
            String value2;
            if (id == -1) {
                if (!PassportActivity.this.checkDiscard()) {
                    if (PassportActivity.this.currentActivityType == 0 || PassportActivity.this.currentActivityType == 5) {
                        PassportActivity.this.callCallback(false);
                    }
                    PassportActivity.this.finishFragment();
                    return;
                }
                return;
            }
            if (id == 1) {
                if (PassportActivity.this.getParentActivity() == null) {
                    return;
                }
                TextView message = new TextView(PassportActivity.this.getParentActivity());
                String str2 = LocaleController.getString("PassportInfo2", R.string.PassportInfo2);
                SpannableStringBuilder spanned = new SpannableStringBuilder(str2);
                int index1 = str2.indexOf(42);
                int index2 = str2.lastIndexOf(42);
                if (index1 != -1 && index2 != -1) {
                    spanned.replace(index2, index2 + 1, (CharSequence) "");
                    spanned.replace(index1, index1 + 1, (CharSequence) "");
                    spanned.setSpan(new URLSpanNoUnderline(LocaleController.getString("PassportInfoUrl", R.string.PassportInfoUrl)) { // from class: im.uwrkaxlmjj.ui.PassportActivity.3.1
                        @Override // im.uwrkaxlmjj.ui.components.URLSpanNoUnderline, android.text.style.URLSpan, android.text.style.ClickableSpan
                        public void onClick(View widget) {
                            PassportActivity.this.dismissCurrentDialog();
                            super.onClick(widget);
                        }
                    }, index1, index2 - 1, 33);
                }
                message.setText(spanned);
                message.setTextSize(1, 16.0f);
                message.setLinkTextColor(Theme.getColor(Theme.key_dialogTextLink));
                message.setHighlightColor(Theme.getColor(Theme.key_dialogLinkSelection));
                message.setPadding(AndroidUtilities.dp(23.0f), 0, AndroidUtilities.dp(23.0f), 0);
                message.setMovementMethod(new AndroidUtilities.LinkMovementMethodMy());
                message.setTextColor(Theme.getColor(Theme.key_dialogTextBlack));
                AlertDialog.Builder builder = new AlertDialog.Builder(PassportActivity.this.getParentActivity());
                builder.setView(message);
                builder.setTitle(LocaleController.getString("PassportInfoTitle", R.string.PassportInfoTitle));
                builder.setNegativeButton(LocaleController.getString("Close", R.string.Close), null);
                PassportActivity.this.showDialog(builder.create());
                return;
            }
            if (id == 2) {
                if (PassportActivity.this.currentActivityType == 5) {
                    PassportActivity.this.onPasswordDone(false);
                    return;
                }
                if (PassportActivity.this.currentActivityType == 7) {
                    PassportActivity.this.views[PassportActivity.this.currentViewNum].onNextPressed();
                    return;
                }
                final Runnable finishRunnable = new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PassportActivity$3$XLsoFluV2yTGBi_n7EF8epxVrDw
                    @Override // java.lang.Runnable
                    public final void run() {
                        this.f$0.lambda$onItemClick$4$PassportActivity$3();
                    }
                };
                final ErrorRunnable errorRunnable = new ErrorRunnable() { // from class: im.uwrkaxlmjj.ui.PassportActivity.3.2
                    @Override // im.uwrkaxlmjj.ui.PassportActivity.ErrorRunnable
                    public void onError(String error, String text) {
                        if ("PHONE_VERIFICATION_NEEDED".equals(error)) {
                            PassportActivity.this.startPhoneVerification(true, text, finishRunnable, this, PassportActivity.this.delegate);
                        } else {
                            PassportActivity.this.showEditDoneProgress(true, false);
                        }
                    }
                };
                if (PassportActivity.this.currentActivityType == 4) {
                    if (PassportActivity.this.useCurrentValue) {
                        value2 = PassportActivity.this.currentEmail;
                    } else if (!PassportActivity.this.checkFieldsForError()) {
                        value2 = PassportActivity.this.inputFields[0].getText().toString();
                    } else {
                        return;
                    }
                    PassportActivity.this.delegate.saveValue(PassportActivity.this.currentType, value2, null, null, null, null, null, null, null, null, finishRunnable, errorRunnable);
                } else if (PassportActivity.this.currentActivityType == 3) {
                    if (PassportActivity.this.useCurrentValue) {
                        value = UserConfig.getInstance(PassportActivity.this.currentAccount).getCurrentUser().phone;
                    } else {
                        if (PassportActivity.this.checkFieldsForError()) {
                            return;
                        }
                        value = PassportActivity.this.inputFields[1].getText().toString() + PassportActivity.this.inputFields[2].getText().toString();
                    }
                    PassportActivity.this.delegate.saveValue(PassportActivity.this.currentType, value, null, null, null, null, null, null, null, null, finishRunnable, errorRunnable);
                } else {
                    if (PassportActivity.this.currentActivityType == 2) {
                        if (PassportActivity.this.uploadingDocuments.isEmpty() && !PassportActivity.this.checkFieldsForError()) {
                            if (PassportActivity.this.isHasNotAnyChanges()) {
                                PassportActivity.this.finishFragment();
                                return;
                            }
                            JSONObject json2 = null;
                            try {
                                if (!PassportActivity.this.documentOnly) {
                                    json2 = new JSONObject();
                                    json2.put("street_line1", PassportActivity.this.inputFields[0].getText().toString());
                                    json2.put("street_line2", PassportActivity.this.inputFields[1].getText().toString());
                                    json2.put("post_code", PassportActivity.this.inputFields[2].getText().toString());
                                    json2.put("city", PassportActivity.this.inputFields[3].getText().toString());
                                    json2.put(RemoteConfigConstants.ResponseFieldKey.STATE, PassportActivity.this.inputFields[4].getText().toString());
                                    json2.put("country_code", PassportActivity.this.currentCitizeship);
                                }
                                json = json2;
                            } catch (Exception e) {
                                json = json2;
                            }
                            if (PassportActivity.this.fieldsErrors != null) {
                                PassportActivity.this.fieldsErrors.clear();
                            }
                            if (PassportActivity.this.documentsErrors != null) {
                                PassportActivity.this.documentsErrors.clear();
                            }
                            PassportActivity.this.delegate.saveValue(PassportActivity.this.currentType, null, json != null ? json.toString() : null, PassportActivity.this.currentDocumentsType, null, PassportActivity.this.documents, PassportActivity.this.selfieDocument, PassportActivity.this.translationDocuments, null, null, finishRunnable, errorRunnable);
                        }
                        return;
                    }
                    if (PassportActivity.this.currentActivityType != 1) {
                        if (PassportActivity.this.currentActivityType == 6) {
                            final TLRPC.TL_account_verifyEmail req = new TLRPC.TL_account_verifyEmail();
                            req.email = (String) PassportActivity.this.currentValues.get("email");
                            req.code = PassportActivity.this.inputFields[0].getText().toString();
                            int reqId = ConnectionsManager.getInstance(PassportActivity.this.currentAccount).sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PassportActivity$3$g5pnJk0wxO4oyh6lc3iLrvLITII
                                @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                                public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                                    this.f$0.lambda$onItemClick$6$PassportActivity$3(finishRunnable, errorRunnable, req, tLObject, tL_error);
                                }
                            });
                            ConnectionsManager.getInstance(PassportActivity.this.currentAccount).bindRequestToGuid(reqId, PassportActivity.this.classGuid);
                        }
                    } else if (!onIdentityDone(finishRunnable, errorRunnable)) {
                        return;
                    }
                }
                PassportActivity.this.showEditDoneProgress(true, true);
            }
        }

        public /* synthetic */ void lambda$onItemClick$4$PassportActivity$3() {
            PassportActivity.this.finishFragment();
        }

        public /* synthetic */ void lambda$onItemClick$6$PassportActivity$3(final Runnable finishRunnable, final ErrorRunnable errorRunnable, final TLRPC.TL_account_verifyEmail req, TLObject response, final TLRPC.TL_error error) {
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PassportActivity$3$ePsvgEddkYLxzXchQ-aEZidhNQM
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$null$5$PassportActivity$3(error, finishRunnable, errorRunnable, req);
                }
            });
        }

        public /* synthetic */ void lambda$null$5$PassportActivity$3(TLRPC.TL_error error, Runnable finishRunnable, ErrorRunnable errorRunnable, TLRPC.TL_account_verifyEmail req) {
            if (error == null) {
                PassportActivity.this.delegate.saveValue(PassportActivity.this.currentType, (String) PassportActivity.this.currentValues.get("email"), null, null, null, null, null, null, null, null, finishRunnable, errorRunnable);
            } else {
                AlertsCreator.processError(PassportActivity.this.currentAccount, error, PassportActivity.this, req, new Object[0]);
                errorRunnable.onError(null, null);
            }
        }
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public boolean dismissDialogOnPause(Dialog dialog) {
        return dialog != this.chatAttachAlert && super.dismissDialogOnPause(dialog);
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void dismissCurrentDialog() {
        if (this.chatAttachAlert != null) {
            Dialog dialog = this.visibleDialog;
            ChatAttachAlert chatAttachAlert = this.chatAttachAlert;
            if (dialog == chatAttachAlert) {
                chatAttachAlert.closeCamera(false);
                this.chatAttachAlert.dismissInternal();
                this.chatAttachAlert.hideCamera(true);
                return;
            }
        }
        super.dismissCurrentDialog();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public String getTranslitString(String value) {
        return LocaleController.getInstance().getTranslitString(value, true);
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
    /* JADX WARN: Removed duplicated region for block: B:56:0x00c3  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public int getFieldCost(java.lang.String r2) {
        /*
            Method dump skipped, instruction units count: 352
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.ui.PassportActivity.getFieldCost(java.lang.String):int");
    }

    private void createPhoneVerificationInterface(Context context) {
        this.actionBar.setTitle(LocaleController.getString("PassportPhone", R.string.PassportPhone));
        FrameLayout frameLayout = new FrameLayout(context);
        this.scrollView.addView(frameLayout, LayoutHelper.createScroll(-1, -2, 51));
        for (int a = 0; a < 3; a++) {
            this.views[a] = new PhoneConfirmationView(context, a + 2);
            this.views[a].setVisibility(8);
            SlideView slideView = this.views[a];
            float f = 18.0f;
            float f2 = AndroidUtilities.isTablet() ? 26.0f : 18.0f;
            if (AndroidUtilities.isTablet()) {
                f = 26.0f;
            }
            frameLayout.addView(slideView, LayoutHelper.createFrame(-1.0f, -1.0f, 51, f2, 30.0f, f, 0.0f));
        }
        Bundle params = new Bundle();
        params.putString("phone", this.currentValues.get("phone"));
        fillNextCodeParams(params, this.currentPhoneVerification, false);
    }

    private void loadPasswordInfo() {
        TLRPC.TL_account_getPassword req = new TLRPC.TL_account_getPassword();
        int reqId = ConnectionsManager.getInstance(this.currentAccount).sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PassportActivity$Ku5IYnQX7-x7R-WJC-y01zamgPI
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                this.f$0.lambda$loadPasswordInfo$4$PassportActivity(tLObject, tL_error);
            }
        });
        ConnectionsManager.getInstance(this.currentAccount).bindRequestToGuid(reqId, this.classGuid);
    }

    public /* synthetic */ void lambda$loadPasswordInfo$4$PassportActivity(final TLObject response, TLRPC.TL_error error) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PassportActivity$S02TY5GPbaOTGu3KL85fiyV67CI
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$3$PassportActivity(response);
            }
        });
    }

    public /* synthetic */ void lambda$null$3$PassportActivity(TLObject response) {
        if (response != null) {
            TLRPC.TL_account_password tL_account_password = (TLRPC.TL_account_password) response;
            this.currentPassword = tL_account_password;
            if (!TwoStepVerificationActivity.canHandleCurrentPassword(tL_account_password, false)) {
                AlertsCreator.showUpdateAppAlert(getParentActivity(), LocaleController.getString("UpdateAppAlert", R.string.UpdateAppAlert), true);
                return;
            }
            TwoStepVerificationActivity.initPasswordNewAlgo(this.currentPassword);
            updatePasswordInterface();
            if (this.inputFieldContainers[0].getVisibility() == 0) {
                this.inputFields[0].requestFocus();
                AndroidUtilities.showKeyboard(this.inputFields[0]);
            }
            if (this.usingSavedPassword == 1) {
                onPasswordDone(true);
            }
        }
    }

    private void createEmailVerificationInterface(Context context) {
        this.actionBar.setTitle(LocaleController.getString("PassportEmail", R.string.PassportEmail));
        this.inputFields = new EditTextBoldCursor[1];
        for (int a = 0; a < 1; a++) {
            ViewGroup container = new FrameLayout(context);
            this.linearLayout2.addView(container, LayoutHelper.createLinear(-1, 50));
            container.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
            this.inputFields[a] = new EditTextBoldCursor(context);
            this.inputFields[a].setTag(Integer.valueOf(a));
            this.inputFields[a].setTextSize(1, 16.0f);
            this.inputFields[a].setHintTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteHintText));
            this.inputFields[a].setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteBlackText));
            this.inputFields[a].setBackgroundDrawable(null);
            this.inputFields[a].setCursorColor(Theme.getColor(Theme.key_windowBackgroundWhiteBlackText));
            this.inputFields[a].setCursorSize(AndroidUtilities.dp(20.0f));
            this.inputFields[a].setCursorWidth(1.5f);
            int i = 3;
            this.inputFields[a].setInputType(3);
            this.inputFields[a].setImeOptions(268435462);
            this.inputFields[a].setHint(LocaleController.getString("PassportEmailCode", R.string.PassportEmailCode));
            EditTextBoldCursor[] editTextBoldCursorArr = this.inputFields;
            editTextBoldCursorArr[a].setSelection(editTextBoldCursorArr[a].length());
            this.inputFields[a].setPadding(0, 0, 0, AndroidUtilities.dp(6.0f));
            EditTextBoldCursor editTextBoldCursor = this.inputFields[a];
            if (LocaleController.isRTL) {
                i = 5;
            }
            editTextBoldCursor.setGravity(i);
            container.addView(this.inputFields[a], LayoutHelper.createFrame(-1.0f, -2.0f, 51, 21.0f, 12.0f, 21.0f, 6.0f));
            this.inputFields[a].setOnEditorActionListener(new TextView.OnEditorActionListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PassportActivity$7ZkMS-AF5G18i7OakIGKGIz4LVw
                @Override // android.widget.TextView.OnEditorActionListener
                public final boolean onEditorAction(TextView textView, int i2, KeyEvent keyEvent) {
                    return this.f$0.lambda$createEmailVerificationInterface$5$PassportActivity(textView, i2, keyEvent);
                }
            });
            this.inputFields[a].addTextChangedListener(new TextWatcher() { // from class: im.uwrkaxlmjj.ui.PassportActivity.6
                @Override // android.text.TextWatcher
                public void beforeTextChanged(CharSequence s, int start, int count, int after) {
                }

                @Override // android.text.TextWatcher
                public void onTextChanged(CharSequence s, int start, int before, int count) {
                }

                @Override // android.text.TextWatcher
                public void afterTextChanged(Editable s) {
                    if (!PassportActivity.this.ignoreOnTextChange && PassportActivity.this.emailCodeLength != 0 && PassportActivity.this.inputFields[0].length() == PassportActivity.this.emailCodeLength) {
                        PassportActivity.this.doneItem.callOnClick();
                    }
                }
            });
        }
        TextInfoPrivacyCell textInfoPrivacyCell = new TextInfoPrivacyCell(context);
        this.bottomCell = textInfoPrivacyCell;
        textInfoPrivacyCell.setBackgroundDrawable(Theme.getThemedDrawable(context, R.drawable.greydivider_bottom, Theme.key_windowBackgroundGrayShadow));
        this.bottomCell.setText(LocaleController.formatString("PassportEmailVerifyInfo", R.string.PassportEmailVerifyInfo, this.currentValues.get("email")));
        this.linearLayout2.addView(this.bottomCell, LayoutHelper.createLinear(-1, -2));
    }

    public /* synthetic */ boolean lambda$createEmailVerificationInterface$5$PassportActivity(TextView textView, int i, KeyEvent keyEvent) {
        if (i == 6 || i == 5) {
            this.doneItem.callOnClick();
            return true;
        }
        return false;
    }

    private void createPasswordInterface(Context context) {
        TLRPC.User botUser = null;
        if (this.currentForm != null) {
            int a = 0;
            while (true) {
                if (a >= this.currentForm.users.size()) {
                    break;
                }
                TLRPC.User user = this.currentForm.users.get(a);
                if (user.id != this.currentBotId) {
                    a++;
                } else {
                    botUser = user;
                    break;
                }
            }
        } else {
            botUser = UserConfig.getInstance(this.currentAccount).getCurrentUser();
        }
        FrameLayout frameLayout = (FrameLayout) this.fragmentView;
        this.actionBar.setTitle(LocaleController.getString("AppPassport", R.string.AppPassport));
        EmptyTextProgressView emptyTextProgressView = new EmptyTextProgressView(context);
        this.emptyView = emptyTextProgressView;
        emptyTextProgressView.showProgress();
        frameLayout.addView(this.emptyView, LayoutHelper.createFrame(-1, -1.0f));
        FrameLayout frameLayout2 = new FrameLayout(context);
        this.passwordAvatarContainer = frameLayout2;
        this.linearLayout2.addView(frameLayout2, LayoutHelper.createLinear(-1, 100));
        BackupImageView avatarImageView = new BackupImageView(context);
        avatarImageView.setRoundRadius(AndroidUtilities.dp(32.0f));
        this.passwordAvatarContainer.addView(avatarImageView, LayoutHelper.createFrame(64.0f, 64.0f, 17, 0.0f, 8.0f, 0.0f, 0.0f));
        AvatarDrawable avatarDrawable = new AvatarDrawable(botUser);
        avatarImageView.setImage(ImageLocation.getForUser(botUser, false), "50_50", avatarDrawable, botUser);
        TextInfoPrivacyCell textInfoPrivacyCell = new TextInfoPrivacyCell(context);
        this.passwordRequestTextView = textInfoPrivacyCell;
        textInfoPrivacyCell.getTextView().setGravity(1);
        if (this.currentBotId == 0) {
            this.passwordRequestTextView.setText(LocaleController.getString("PassportSelfRequest", R.string.PassportSelfRequest));
        } else {
            this.passwordRequestTextView.setText(AndroidUtilities.replaceTags(LocaleController.formatString("PassportRequest", R.string.PassportRequest, UserObject.getFirstName(botUser))));
        }
        ((FrameLayout.LayoutParams) this.passwordRequestTextView.getTextView().getLayoutParams()).gravity = 1;
        this.linearLayout2.addView(this.passwordRequestTextView, LayoutHelper.createFrame(-2.0f, -2.0f, (LocaleController.isRTL ? 5 : 3) | 48, 21.0f, 0.0f, 21.0f, 0.0f));
        ImageView imageView = new ImageView(context);
        this.noPasswordImageView = imageView;
        imageView.setImageResource(R.drawable.no_password);
        this.noPasswordImageView.setColorFilter(new PorterDuffColorFilter(Theme.getColor(Theme.key_chat_messagePanelIcons), PorterDuff.Mode.MULTIPLY));
        this.linearLayout2.addView(this.noPasswordImageView, LayoutHelper.createLinear(-2, -2, 49, 0, 13, 0, 0));
        TextView textView = new TextView(context);
        this.noPasswordTextView = textView;
        textView.setTextSize(1, 14.0f);
        this.noPasswordTextView.setGravity(1);
        this.noPasswordTextView.setPadding(AndroidUtilities.dp(21.0f), AndroidUtilities.dp(10.0f), AndroidUtilities.dp(21.0f), AndroidUtilities.dp(17.0f));
        this.noPasswordTextView.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteGrayText4));
        this.noPasswordTextView.setText(LocaleController.getString("AppPassportCreatePasswordInfo", R.string.AppPassportCreatePasswordInfo));
        this.linearLayout2.addView(this.noPasswordTextView, LayoutHelper.createFrame(-2.0f, -2.0f, (LocaleController.isRTL ? 5 : 3) | 48, 21.0f, 10.0f, 21.0f, 0.0f));
        TextView textView2 = new TextView(context);
        this.noPasswordSetTextView = textView2;
        textView2.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteBlueText5));
        this.noPasswordSetTextView.setGravity(17);
        this.noPasswordSetTextView.setTextSize(1, 16.0f);
        this.noPasswordSetTextView.setTypeface(AndroidUtilities.getTypeface("fonts/rmedium.ttf"));
        this.noPasswordSetTextView.setText(LocaleController.getString("AppPassportCreatePassword", R.string.AppPassportCreatePassword));
        this.linearLayout2.addView(this.noPasswordSetTextView, LayoutHelper.createFrame(-1.0f, 24.0f, (LocaleController.isRTL ? 5 : 3) | 48, 21.0f, 9.0f, 21.0f, 0.0f));
        this.noPasswordSetTextView.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PassportActivity$9henhxBjNVvwfCj-E6rOvm59xhA
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                this.f$0.lambda$createPasswordInterface$6$PassportActivity(view);
            }
        });
        this.inputFields = new EditTextBoldCursor[1];
        this.inputFieldContainers = new ViewGroup[1];
        for (int a2 = 0; a2 < 1; a2++) {
            this.inputFieldContainers[a2] = new FrameLayout(context);
            this.linearLayout2.addView(this.inputFieldContainers[a2], LayoutHelper.createLinear(-1, 50));
            this.inputFieldContainers[a2].setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
            this.inputFields[a2] = new EditTextBoldCursor(context);
            this.inputFields[a2].setTag(Integer.valueOf(a2));
            this.inputFields[a2].setTextSize(1, 16.0f);
            this.inputFields[a2].setHintTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteHintText));
            this.inputFields[a2].setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteBlackText));
            this.inputFields[a2].setBackgroundDrawable(null);
            this.inputFields[a2].setCursorColor(Theme.getColor(Theme.key_windowBackgroundWhiteBlackText));
            this.inputFields[a2].setCursorSize(AndroidUtilities.dp(20.0f));
            this.inputFields[a2].setCursorWidth(1.5f);
            this.inputFields[a2].setInputType(TsExtractor.TS_STREAM_TYPE_AC3);
            this.inputFields[a2].setMaxLines(1);
            this.inputFields[a2].setLines(1);
            this.inputFields[a2].setSingleLine(true);
            this.inputFields[a2].setTransformationMethod(PasswordTransformationMethod.getInstance());
            this.inputFields[a2].setTypeface(Typeface.DEFAULT);
            this.inputFields[a2].setImeOptions(268435462);
            this.inputFields[a2].setPadding(0, 0, 0, AndroidUtilities.dp(6.0f));
            this.inputFields[a2].setGravity(LocaleController.isRTL ? 5 : 3);
            this.inputFieldContainers[a2].addView(this.inputFields[a2], LayoutHelper.createFrame(-1.0f, -2.0f, 51, 21.0f, 12.0f, 21.0f, 6.0f));
            this.inputFields[a2].setOnEditorActionListener(new TextView.OnEditorActionListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PassportActivity$jqo8R5sbjBKmxD8LFsuW3nfskjo
                @Override // android.widget.TextView.OnEditorActionListener
                public final boolean onEditorAction(TextView textView3, int i, KeyEvent keyEvent) {
                    return this.f$0.lambda$createPasswordInterface$7$PassportActivity(textView3, i, keyEvent);
                }
            });
            this.inputFields[a2].setCustomSelectionActionModeCallback(new ActionMode.Callback() { // from class: im.uwrkaxlmjj.ui.PassportActivity.7
                @Override // android.view.ActionMode.Callback
                public boolean onPrepareActionMode(ActionMode mode, Menu menu) {
                    return false;
                }

                @Override // android.view.ActionMode.Callback
                public void onDestroyActionMode(ActionMode mode) {
                }

                @Override // android.view.ActionMode.Callback
                public boolean onCreateActionMode(ActionMode mode, Menu menu) {
                    return false;
                }

                @Override // android.view.ActionMode.Callback
                public boolean onActionItemClicked(ActionMode mode, MenuItem item) {
                    return false;
                }
            });
        }
        TextInfoPrivacyCell textInfoPrivacyCell2 = new TextInfoPrivacyCell(context);
        this.passwordInfoRequestTextView = textInfoPrivacyCell2;
        textInfoPrivacyCell2.setBackgroundDrawable(Theme.getThemedDrawable(context, R.drawable.greydivider_bottom, Theme.key_windowBackgroundGrayShadow));
        this.passwordInfoRequestTextView.setText(LocaleController.formatString("PassportRequestPasswordInfo", R.string.PassportRequestPasswordInfo, new Object[0]));
        this.linearLayout2.addView(this.passwordInfoRequestTextView, LayoutHelper.createLinear(-1, -2));
        TextView textView3 = new TextView(context);
        this.passwordForgotButton = textView3;
        textView3.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteBlueText4));
        this.passwordForgotButton.setTextSize(1, 14.0f);
        this.passwordForgotButton.setText(LocaleController.getString("ForgotPassword", R.string.ForgotPassword));
        this.passwordForgotButton.setPadding(0, 0, 0, 0);
        this.linearLayout2.addView(this.passwordForgotButton, LayoutHelper.createLinear(-2, 30, (LocaleController.isRTL ? 5 : 3) | 48, 21, 0, 21, 0));
        this.passwordForgotButton.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PassportActivity$qQ9zlTpnk_7RFZVbn_ww4NP5-Tk
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                this.f$0.lambda$createPasswordInterface$12$PassportActivity(view);
            }
        });
        updatePasswordInterface();
    }

    public /* synthetic */ void lambda$createPasswordInterface$6$PassportActivity(View v) {
        TwoStepVerificationActivity activity = new TwoStepVerificationActivity(this.currentAccount, 1);
        activity.setCloseAfterSet(true);
        activity.setCurrentPasswordInfo(new byte[0], this.currentPassword);
        presentFragment(activity);
    }

    public /* synthetic */ boolean lambda$createPasswordInterface$7$PassportActivity(TextView textView, int i, KeyEvent keyEvent) {
        if (i == 5 || i == 6) {
            this.doneItem.callOnClick();
            return true;
        }
        return false;
    }

    public /* synthetic */ void lambda$createPasswordInterface$12$PassportActivity(View v) {
        if (this.currentPassword.has_recovery) {
            needShowProgress();
            TLRPC.TL_auth_requestPasswordRecovery req = new TLRPC.TL_auth_requestPasswordRecovery();
            int reqId = ConnectionsManager.getInstance(this.currentAccount).sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PassportActivity$1h-AJ-Hs1EwCAePOehPr6ILbWIk
                @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                    this.f$0.lambda$null$10$PassportActivity(tLObject, tL_error);
                }
            }, 10);
            ConnectionsManager.getInstance(this.currentAccount).bindRequestToGuid(reqId, this.classGuid);
            return;
        }
        if (getParentActivity() == null) {
            return;
        }
        AlertDialog.Builder builder = new AlertDialog.Builder(getParentActivity());
        builder.setPositiveButton(LocaleController.getString("OK", R.string.OK), null);
        builder.setNegativeButton(LocaleController.getString("RestorePasswordResetAccount", R.string.RestorePasswordResetAccount), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PassportActivity$pTgYZUW9G8L-P36hwGawOhOm8vc
            @Override // android.content.DialogInterface.OnClickListener
            public final void onClick(DialogInterface dialogInterface, int i) {
                this.f$0.lambda$null$11$PassportActivity(dialogInterface, i);
            }
        });
        builder.setTitle(LocaleController.getString("RestorePasswordNoEmailTitle", R.string.RestorePasswordNoEmailTitle));
        builder.setMessage(LocaleController.getString("RestorePasswordNoEmailText", R.string.RestorePasswordNoEmailText));
        showDialog(builder.create());
    }

    public /* synthetic */ void lambda$null$10$PassportActivity(final TLObject response, final TLRPC.TL_error error) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PassportActivity$O7FAHOfOpdl2ayqDqHJ7HYfmE74
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$9$PassportActivity(error, response);
            }
        });
    }

    public /* synthetic */ void lambda$null$9$PassportActivity(TLRPC.TL_error error, TLObject response) {
        String timeString;
        needHideProgress();
        if (error == null) {
            final TLRPC.TL_auth_passwordRecovery res = (TLRPC.TL_auth_passwordRecovery) response;
            AlertDialog.Builder builder = new AlertDialog.Builder(getParentActivity());
            builder.setMessage(LocaleController.formatString("RestoreEmailSent", R.string.RestoreEmailSent, res.email_pattern));
            builder.setTitle(LocaleController.getString("AppName", R.string.AppName));
            builder.setPositiveButton(LocaleController.getString("OK", R.string.OK), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PassportActivity$MQ8uWZOV2XnFCu1Ecc1oFwbAXH8
                @Override // android.content.DialogInterface.OnClickListener
                public final void onClick(DialogInterface dialogInterface, int i) {
                    this.f$0.lambda$null$8$PassportActivity(res, dialogInterface, i);
                }
            });
            Dialog dialog = showDialog(builder.create());
            if (dialog != null) {
                dialog.setCanceledOnTouchOutside(false);
                dialog.setCancelable(false);
                return;
            }
            return;
        }
        if (error.text.startsWith("FLOOD_WAIT")) {
            int time = Utilities.parseInt(error.text).intValue();
            if (time < 60) {
                timeString = LocaleController.formatPluralString("Seconds", time);
            } else {
                timeString = LocaleController.formatPluralString("Minutes", time / 60);
            }
            showAlertWithText(LocaleController.getString("AppName", R.string.AppName), LocaleController.formatString("FloodWaitTime", R.string.FloodWaitTime, timeString));
            return;
        }
        showAlertWithText(LocaleController.getString("AppName", R.string.AppName), error.text);
    }

    public /* synthetic */ void lambda$null$8$PassportActivity(TLRPC.TL_auth_passwordRecovery res, DialogInterface dialogInterface, int i) {
        TwoStepVerificationActivity fragment = new TwoStepVerificationActivity(this.currentAccount, 1);
        fragment.setRecoveryParams(this.currentPassword);
        this.currentPassword.email_unconfirmed_pattern = res.email_pattern;
        presentFragment(fragment);
    }

    public /* synthetic */ void lambda$null$11$PassportActivity(DialogInterface dialog, int which) {
        Browser.openUrl(getParentActivity(), "https://m12345.com/deactivate?phone=" + UserConfig.getInstance(this.currentAccount).getClientPhone());
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void onPasswordDone(final boolean saved) {
        final String textPassword;
        if (saved) {
            textPassword = null;
        } else {
            textPassword = this.inputFields[0].getText().toString();
            if (TextUtils.isEmpty(textPassword)) {
                onPasscodeError(false);
                return;
            }
            showEditDoneProgress(true, true);
        }
        Utilities.globalQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PassportActivity$ivXuvWAAQN2Ii322XVZmDi9RnfI
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$onPasswordDone$13$PassportActivity(saved, textPassword);
            }
        });
    }

    public /* synthetic */ void lambda$onPasswordDone$13$PassportActivity(boolean saved, String textPassword) {
        byte[] x_bytes;
        TLRPC.TL_account_getPasswordSettings req = new TLRPC.TL_account_getPasswordSettings();
        if (saved) {
            x_bytes = this.savedPasswordHash;
        } else if (this.currentPassword.current_algo instanceof TLRPC.TL_passwordKdfAlgoSHA256SHA256PBKDF2HMACSHA512iter100000SHA256ModPow) {
            byte[] passwordBytes = AndroidUtilities.getStringBytes(textPassword);
            TLRPC.TL_passwordKdfAlgoSHA256SHA256PBKDF2HMACSHA512iter100000SHA256ModPow algo = (TLRPC.TL_passwordKdfAlgoSHA256SHA256PBKDF2HMACSHA512iter100000SHA256ModPow) this.currentPassword.current_algo;
            x_bytes = SRPHelper.getX(passwordBytes, algo);
        } else {
            x_bytes = null;
        }
        RequestDelegate requestDelegate = new AnonymousClass8(saved, x_bytes, req, textPassword);
        if (this.currentPassword.current_algo instanceof TLRPC.TL_passwordKdfAlgoSHA256SHA256PBKDF2HMACSHA512iter100000SHA256ModPow) {
            TLRPC.TL_passwordKdfAlgoSHA256SHA256PBKDF2HMACSHA512iter100000SHA256ModPow algo2 = (TLRPC.TL_passwordKdfAlgoSHA256SHA256PBKDF2HMACSHA512iter100000SHA256ModPow) this.currentPassword.current_algo;
            req.password = SRPHelper.startCheck(x_bytes, this.currentPassword.srp_id, this.currentPassword.srp_B, algo2);
            if (req.password == null) {
                TLRPC.TL_error error = new TLRPC.TL_error();
                error.text = "ALGO_INVALID";
                requestDelegate.run(null, error);
                return;
            } else {
                int reqId = ConnectionsManager.getInstance(this.currentAccount).sendRequest(req, requestDelegate, 10);
                ConnectionsManager.getInstance(this.currentAccount).bindRequestToGuid(reqId, this.classGuid);
                return;
            }
        }
        TLRPC.TL_error error2 = new TLRPC.TL_error();
        error2.text = "PASSWORD_HASH_INVALID";
        requestDelegate.run(null, error2);
    }

    /* JADX INFO: renamed from: im.uwrkaxlmjj.ui.PassportActivity$8, reason: invalid class name */
    class AnonymousClass8 implements RequestDelegate {
        final /* synthetic */ TLRPC.TL_account_getPasswordSettings val$req;
        final /* synthetic */ boolean val$saved;
        final /* synthetic */ String val$textPassword;
        final /* synthetic */ byte[] val$x_bytes;

        AnonymousClass8(boolean z, byte[] bArr, TLRPC.TL_account_getPasswordSettings tL_account_getPasswordSettings, String str) {
            this.val$saved = z;
            this.val$x_bytes = bArr;
            this.val$req = tL_account_getPasswordSettings;
            this.val$textPassword = str;
        }

        private void openRequestInterface() {
            int type;
            if (PassportActivity.this.inputFields == null) {
                return;
            }
            if (!this.val$saved) {
                UserConfig.getInstance(PassportActivity.this.currentAccount).savePassword(this.val$x_bytes, PassportActivity.this.saltedPassword);
            }
            AndroidUtilities.hideKeyboard(PassportActivity.this.inputFields[0]);
            PassportActivity.this.ignoreOnFailure = true;
            if (PassportActivity.this.currentBotId == 0) {
                type = 8;
            } else {
                type = 0;
            }
            PassportActivity activity = new PassportActivity(type, PassportActivity.this.currentBotId, PassportActivity.this.currentScope, PassportActivity.this.currentPublicKey, PassportActivity.this.currentPayload, PassportActivity.this.currentNonce, PassportActivity.this.currentCallbackUrl, PassportActivity.this.currentForm, PassportActivity.this.currentPassword);
            activity.currentEmail = PassportActivity.this.currentEmail;
            activity.currentAccount = PassportActivity.this.currentAccount;
            activity.saltedPassword = PassportActivity.this.saltedPassword;
            activity.secureSecret = PassportActivity.this.secureSecret;
            activity.secureSecretId = PassportActivity.this.secureSecretId;
            activity.needActivityResult = PassportActivity.this.needActivityResult;
            if (PassportActivity.this.parentLayout != null && PassportActivity.this.parentLayout.checkTransitionAnimation()) {
                PassportActivity.this.presentAfterAnimation = activity;
            } else {
                PassportActivity.this.presentFragment(activity, true);
            }
        }

        private void resetSecret() {
            TLRPC.TL_account_updatePasswordSettings req2 = new TLRPC.TL_account_updatePasswordSettings();
            if (PassportActivity.this.currentPassword.current_algo instanceof TLRPC.TL_passwordKdfAlgoSHA256SHA256PBKDF2HMACSHA512iter100000SHA256ModPow) {
                TLRPC.TL_passwordKdfAlgoSHA256SHA256PBKDF2HMACSHA512iter100000SHA256ModPow algo = (TLRPC.TL_passwordKdfAlgoSHA256SHA256PBKDF2HMACSHA512iter100000SHA256ModPow) PassportActivity.this.currentPassword.current_algo;
                req2.password = SRPHelper.startCheck(this.val$x_bytes, PassportActivity.this.currentPassword.srp_id, PassportActivity.this.currentPassword.srp_B, algo);
            }
            req2.new_settings = new TLRPC.TL_account_passwordInputSettings();
            req2.new_settings.new_secure_settings = new TLRPC.TL_secureSecretSettings();
            req2.new_settings.new_secure_settings.secure_secret = new byte[0];
            req2.new_settings.new_secure_settings.secure_algo = new TLRPC.TL_securePasswordKdfAlgoUnknown();
            req2.new_settings.new_secure_settings.secure_secret_id = 0L;
            req2.new_settings.flags |= 4;
            ConnectionsManager.getInstance(PassportActivity.this.currentAccount).sendRequest(this.val$req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PassportActivity$8$qYAqoC87beNP3FHhQn4vRtAU_rQ
                @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                    this.f$0.lambda$resetSecret$3$PassportActivity$8(tLObject, tL_error);
                }
            });
        }

        public /* synthetic */ void lambda$resetSecret$3$PassportActivity$8(TLObject response, final TLRPC.TL_error error) {
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PassportActivity$8$RJRonkNuIcgTs14R4FSxZPmM870
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$null$2$PassportActivity$8(error);
                }
            });
        }

        public /* synthetic */ void lambda$null$2$PassportActivity$8(TLRPC.TL_error error) {
            if (error != null && "SRP_ID_INVALID".equals(error.text)) {
                TLRPC.TL_account_getPassword getPasswordReq = new TLRPC.TL_account_getPassword();
                ConnectionsManager.getInstance(PassportActivity.this.currentAccount).sendRequest(getPasswordReq, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PassportActivity$8$9vMgjeTXC5WtnNyUwqpmSiYRI1E
                    @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                    public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                        this.f$0.lambda$null$1$PassportActivity$8(tLObject, tL_error);
                    }
                }, 8);
            } else {
                generateNewSecret();
            }
        }

        public /* synthetic */ void lambda$null$1$PassportActivity$8(final TLObject response2, final TLRPC.TL_error error2) {
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PassportActivity$8$CiAcSHkGh75CNTUCeKSrPNIZhwY
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$null$0$PassportActivity$8(error2, response2);
                }
            });
        }

        public /* synthetic */ void lambda$null$0$PassportActivity$8(TLRPC.TL_error error2, TLObject response2) {
            if (error2 == null) {
                PassportActivity.this.currentPassword = (TLRPC.TL_account_password) response2;
                TwoStepVerificationActivity.initPasswordNewAlgo(PassportActivity.this.currentPassword);
                resetSecret();
            }
        }

        private void generateNewSecret() {
            DispatchQueue dispatchQueue = Utilities.globalQueue;
            final byte[] bArr = this.val$x_bytes;
            final String str = this.val$textPassword;
            dispatchQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PassportActivity$8$ick3-XogZa3mQhNfiOwRSUcrs3Q
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$generateNewSecret$8$PassportActivity$8(bArr, str);
                }
            });
        }

        public /* synthetic */ void lambda$generateNewSecret$8$PassportActivity$8(byte[] x_bytes, String textPassword) {
            Utilities.random.setSeed(PassportActivity.this.currentPassword.secure_random);
            TLRPC.TL_account_updatePasswordSettings req1 = new TLRPC.TL_account_updatePasswordSettings();
            if (PassportActivity.this.currentPassword.current_algo instanceof TLRPC.TL_passwordKdfAlgoSHA256SHA256PBKDF2HMACSHA512iter100000SHA256ModPow) {
                TLRPC.TL_passwordKdfAlgoSHA256SHA256PBKDF2HMACSHA512iter100000SHA256ModPow algo = (TLRPC.TL_passwordKdfAlgoSHA256SHA256PBKDF2HMACSHA512iter100000SHA256ModPow) PassportActivity.this.currentPassword.current_algo;
                req1.password = SRPHelper.startCheck(x_bytes, PassportActivity.this.currentPassword.srp_id, PassportActivity.this.currentPassword.srp_B, algo);
            }
            req1.new_settings = new TLRPC.TL_account_passwordInputSettings();
            PassportActivity passportActivity = PassportActivity.this;
            passportActivity.secureSecret = passportActivity.getRandomSecret();
            PassportActivity passportActivity2 = PassportActivity.this;
            passportActivity2.secureSecretId = Utilities.bytesToLong(Utilities.computeSHA256(passportActivity2.secureSecret));
            if (PassportActivity.this.currentPassword.new_secure_algo instanceof TLRPC.TL_securePasswordKdfAlgoPBKDF2HMACSHA512iter100000) {
                TLRPC.TL_securePasswordKdfAlgoPBKDF2HMACSHA512iter100000 newAlgo = (TLRPC.TL_securePasswordKdfAlgoPBKDF2HMACSHA512iter100000) PassportActivity.this.currentPassword.new_secure_algo;
                PassportActivity.this.saltedPassword = Utilities.computePBKDF2(AndroidUtilities.getStringBytes(textPassword), newAlgo.salt);
                byte[] key = new byte[32];
                System.arraycopy(PassportActivity.this.saltedPassword, 0, key, 0, 32);
                byte[] iv = new byte[16];
                System.arraycopy(PassportActivity.this.saltedPassword, 32, iv, 0, 16);
                Utilities.aesCbcEncryptionByteArraySafe(PassportActivity.this.secureSecret, key, iv, 0, PassportActivity.this.secureSecret.length, 0, 1);
                req1.new_settings.new_secure_settings = new TLRPC.TL_secureSecretSettings();
                req1.new_settings.new_secure_settings.secure_algo = newAlgo;
                req1.new_settings.new_secure_settings.secure_secret = PassportActivity.this.secureSecret;
                req1.new_settings.new_secure_settings.secure_secret_id = PassportActivity.this.secureSecretId;
                req1.new_settings.flags |= 4;
            }
            ConnectionsManager.getInstance(PassportActivity.this.currentAccount).sendRequest(req1, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PassportActivity$8$xRSPgTlwl2s3C5jN6AfVwaYDsCQ
                @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                    this.f$0.lambda$null$7$PassportActivity$8(tLObject, tL_error);
                }
            });
        }

        public /* synthetic */ void lambda$null$7$PassportActivity$8(TLObject response, final TLRPC.TL_error error) {
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PassportActivity$8$-y6Z1xORFfMMEtA4yHJE3IzKb9w
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$null$6$PassportActivity$8(error);
                }
            });
        }

        public /* synthetic */ void lambda$null$6$PassportActivity$8(TLRPC.TL_error error) {
            if (error == null || !"SRP_ID_INVALID".equals(error.text)) {
                if (PassportActivity.this.currentForm == null) {
                    PassportActivity.this.currentForm = new TLRPC.TL_account_authorizationForm();
                }
                openRequestInterface();
                return;
            }
            TLRPC.TL_account_getPassword getPasswordReq = new TLRPC.TL_account_getPassword();
            ConnectionsManager.getInstance(PassportActivity.this.currentAccount).sendRequest(getPasswordReq, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PassportActivity$8$ZoztDW2_T5WrrIXEmDITDqmpchc
                @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                    this.f$0.lambda$null$5$PassportActivity$8(tLObject, tL_error);
                }
            }, 8);
        }

        public /* synthetic */ void lambda$null$5$PassportActivity$8(final TLObject response2, final TLRPC.TL_error error2) {
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PassportActivity$8$5tQk5Ii0CA90eiXvmqwfxLOwSr8
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$null$4$PassportActivity$8(error2, response2);
                }
            });
        }

        public /* synthetic */ void lambda$null$4$PassportActivity$8(TLRPC.TL_error error2, TLObject response2) {
            if (error2 == null) {
                PassportActivity.this.currentPassword = (TLRPC.TL_account_password) response2;
                TwoStepVerificationActivity.initPasswordNewAlgo(PassportActivity.this.currentPassword);
                generateNewSecret();
            }
        }

        @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
        public void run(final TLObject response, final TLRPC.TL_error error) {
            if (error != null && "SRP_ID_INVALID".equals(error.text)) {
                TLRPC.TL_account_getPassword getPasswordReq = new TLRPC.TL_account_getPassword();
                ConnectionsManager connectionsManager = ConnectionsManager.getInstance(PassportActivity.this.currentAccount);
                final boolean z = this.val$saved;
                connectionsManager.sendRequest(getPasswordReq, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PassportActivity$8$fZxW0HQcoyLl-BDNy7gFQvbe1ks
                    @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                    public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                        this.f$0.lambda$run$10$PassportActivity$8(z, tLObject, tL_error);
                    }
                }, 8);
                return;
            }
            if (error == null) {
                DispatchQueue dispatchQueue = Utilities.globalQueue;
                final String str = this.val$textPassword;
                final boolean z2 = this.val$saved;
                dispatchQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PassportActivity$8$Oxjhj93Gd6TNx31Q8u9j8ibCayE
                    @Override // java.lang.Runnable
                    public final void run() {
                        this.f$0.lambda$run$15$PassportActivity$8(response, str, z2);
                    }
                });
                return;
            }
            final boolean z3 = this.val$saved;
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PassportActivity$8$9BfGMHBgRDwAxoRi46dItwBEZww
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$run$16$PassportActivity$8(z3, error);
                }
            });
        }

        public /* synthetic */ void lambda$run$10$PassportActivity$8(final boolean saved, final TLObject response2, final TLRPC.TL_error error2) {
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PassportActivity$8$tjjJd2BErQ05wB2iWsjrQOcWcQQ
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$null$9$PassportActivity$8(error2, response2, saved);
                }
            });
        }

        public /* synthetic */ void lambda$null$9$PassportActivity$8(TLRPC.TL_error error2, TLObject response2, boolean saved) {
            if (error2 == null) {
                PassportActivity.this.currentPassword = (TLRPC.TL_account_password) response2;
                TwoStepVerificationActivity.initPasswordNewAlgo(PassportActivity.this.currentPassword);
                PassportActivity.this.onPasswordDone(saved);
            }
        }

        public /* synthetic */ void lambda$run$15$PassportActivity$8(TLObject response, String textPassword, final boolean saved) {
            final byte[] secure_salt;
            final TLRPC.TL_account_passwordSettings settings = (TLRPC.TL_account_passwordSettings) response;
            if (settings.secure_settings == null) {
                if (PassportActivity.this.currentPassword.new_secure_algo instanceof TLRPC.TL_securePasswordKdfAlgoPBKDF2HMACSHA512iter100000) {
                    TLRPC.TL_securePasswordKdfAlgoPBKDF2HMACSHA512iter100000 algo = (TLRPC.TL_securePasswordKdfAlgoPBKDF2HMACSHA512iter100000) PassportActivity.this.currentPassword.new_secure_algo;
                    secure_salt = algo.salt;
                    PassportActivity.this.saltedPassword = Utilities.computePBKDF2(AndroidUtilities.getStringBytes(textPassword), algo.salt);
                } else {
                    secure_salt = new byte[0];
                }
                PassportActivity.this.secureSecret = null;
                PassportActivity.this.secureSecretId = 0L;
            } else {
                PassportActivity.this.secureSecret = settings.secure_settings.secure_secret;
                PassportActivity.this.secureSecretId = settings.secure_settings.secure_secret_id;
                if (settings.secure_settings.secure_algo instanceof TLRPC.TL_securePasswordKdfAlgoSHA512) {
                    secure_salt = ((TLRPC.TL_securePasswordKdfAlgoSHA512) settings.secure_settings.secure_algo).salt;
                    PassportActivity.this.saltedPassword = Utilities.computeSHA512(secure_salt, AndroidUtilities.getStringBytes(textPassword), secure_salt);
                } else if (settings.secure_settings.secure_algo instanceof TLRPC.TL_securePasswordKdfAlgoPBKDF2HMACSHA512iter100000) {
                    TLRPC.TL_securePasswordKdfAlgoPBKDF2HMACSHA512iter100000 algo2 = (TLRPC.TL_securePasswordKdfAlgoPBKDF2HMACSHA512iter100000) settings.secure_settings.secure_algo;
                    secure_salt = algo2.salt;
                    PassportActivity.this.saltedPassword = Utilities.computePBKDF2(AndroidUtilities.getStringBytes(textPassword), algo2.salt);
                } else {
                    if (settings.secure_settings.secure_algo instanceof TLRPC.TL_securePasswordKdfAlgoUnknown) {
                        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PassportActivity$8$OD59befSvBq3xnEQYG1LywAqbXU
                            @Override // java.lang.Runnable
                            public final void run() {
                                this.f$0.lambda$null$11$PassportActivity$8();
                            }
                        });
                        return;
                    }
                    secure_salt = new byte[0];
                }
            }
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PassportActivity$8$R672k46-uYV-aLX1lYpAs-HDTPs
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$null$14$PassportActivity$8(settings, saved, secure_salt);
                }
            });
        }

        public /* synthetic */ void lambda$null$11$PassportActivity$8() {
            AlertsCreator.showUpdateAppAlert(PassportActivity.this.getParentActivity(), LocaleController.getString("UpdateAppAlert", R.string.UpdateAppAlert), true);
        }

        public /* synthetic */ void lambda$null$14$PassportActivity$8(TLRPC.TL_account_passwordSettings settings, boolean saved, byte[] secure_salt) {
            PassportActivity.this.currentEmail = settings.email;
            if (saved) {
                PassportActivity passportActivity = PassportActivity.this;
                passportActivity.saltedPassword = passportActivity.savedSaltedPassword;
            }
            PassportActivity passportActivity2 = PassportActivity.this;
            if (PassportActivity.checkSecret(passportActivity2.decryptSecret(passportActivity2.secureSecret, PassportActivity.this.saltedPassword), Long.valueOf(PassportActivity.this.secureSecretId)) && secure_salt.length != 0 && PassportActivity.this.secureSecretId != 0) {
                if (PassportActivity.this.currentBotId == 0) {
                    TLRPC.TL_account_getAllSecureValues req12 = new TLRPC.TL_account_getAllSecureValues();
                    ConnectionsManager.getInstance(PassportActivity.this.currentAccount).sendRequest(req12, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PassportActivity$8$9GWW6k9EEW0_RWvVw1MkwqlqRfc
                        @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                        public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                            this.f$0.lambda$null$13$PassportActivity$8(tLObject, tL_error);
                        }
                    });
                    return;
                } else {
                    openRequestInterface();
                    return;
                }
            }
            if (saved) {
                UserConfig.getInstance(PassportActivity.this.currentAccount).resetSavedPassword();
                PassportActivity.this.usingSavedPassword = 0;
                PassportActivity.this.updatePasswordInterface();
                return;
            }
            if (PassportActivity.this.currentForm != null) {
                PassportActivity.this.currentForm.values.clear();
                PassportActivity.this.currentForm.errors.clear();
            }
            if (PassportActivity.this.secureSecret == null || PassportActivity.this.secureSecret.length == 0) {
                generateNewSecret();
            } else {
                resetSecret();
            }
        }

        public /* synthetic */ void lambda$null$13$PassportActivity$8(final TLObject response1, final TLRPC.TL_error error1) {
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PassportActivity$8$DnwZCPmQx5OEMKuwzRNcol3UkqE
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$null$12$PassportActivity$8(response1, error1);
                }
            });
        }

        public /* synthetic */ void lambda$null$12$PassportActivity$8(TLObject response1, TLRPC.TL_error error1) {
            if (response1 != null) {
                PassportActivity.this.currentForm = new TLRPC.TL_account_authorizationForm();
                TLRPC.Vector vector = (TLRPC.Vector) response1;
                int size = vector.objects.size();
                for (int a = 0; a < size; a++) {
                    PassportActivity.this.currentForm.values.add((TLRPC.TL_secureValue) vector.objects.get(a));
                }
                openRequestInterface();
                return;
            }
            if (!"APP_VERSION_OUTDATED".equals(error1.text)) {
                PassportActivity.this.showAlertWithText(LocaleController.getString("AppName", R.string.AppName), error1.text);
            } else {
                AlertsCreator.showUpdateAppAlert(PassportActivity.this.getParentActivity(), LocaleController.getString("UpdateAppAlert", R.string.UpdateAppAlert), true);
            }
            PassportActivity.this.showEditDoneProgress(true, false);
        }

        public /* synthetic */ void lambda$run$16$PassportActivity$8(boolean saved, TLRPC.TL_error error) {
            String timeString;
            if (saved) {
                UserConfig.getInstance(PassportActivity.this.currentAccount).resetSavedPassword();
                PassportActivity.this.usingSavedPassword = 0;
                PassportActivity.this.updatePasswordInterface();
                if (PassportActivity.this.inputFieldContainers != null && PassportActivity.this.inputFieldContainers[0].getVisibility() == 0) {
                    PassportActivity.this.inputFields[0].requestFocus();
                    AndroidUtilities.showKeyboard(PassportActivity.this.inputFields[0]);
                    return;
                }
                return;
            }
            PassportActivity.this.showEditDoneProgress(true, false);
            if (error.text.equals("PASSWORD_HASH_INVALID")) {
                PassportActivity.this.onPasscodeError(true);
                return;
            }
            if (!error.text.startsWith("FLOOD_WAIT")) {
                PassportActivity.this.showAlertWithText(LocaleController.getString("AppName", R.string.AppName), error.text);
                return;
            }
            int time = Utilities.parseInt(error.text).intValue();
            if (time < 60) {
                timeString = LocaleController.formatPluralString("Seconds", time);
            } else {
                timeString = LocaleController.formatPluralString("Minutes", time / 60);
            }
            PassportActivity.this.showAlertWithText(LocaleController.getString("AppName", R.string.AppName), LocaleController.formatString("FloodWaitTime", R.string.FloodWaitTime, timeString));
        }
    }

    private boolean isPersonalDocument(TLRPC.SecureValueType type) {
        return (type instanceof TLRPC.TL_secureValueTypeDriverLicense) || (type instanceof TLRPC.TL_secureValueTypePassport) || (type instanceof TLRPC.TL_secureValueTypeInternalPassport) || (type instanceof TLRPC.TL_secureValueTypeIdentityCard);
    }

    private boolean isAddressDocument(TLRPC.SecureValueType type) {
        return (type instanceof TLRPC.TL_secureValueTypeUtilityBill) || (type instanceof TLRPC.TL_secureValueTypeBankStatement) || (type instanceof TLRPC.TL_secureValueTypePassportRegistration) || (type instanceof TLRPC.TL_secureValueTypeTemporaryRegistration) || (type instanceof TLRPC.TL_secureValueTypeRentalAgreement);
    }

    /* JADX WARN: Removed duplicated region for block: B:139:0x039f  */
    /* JADX WARN: Removed duplicated region for block: B:140:0x03a2  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    private void createRequestInterface(android.content.Context r32) {
        /*
            Method dump skipped, instruction units count: 1374
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.ui.PassportActivity.createRequestInterface(android.content.Context):void");
    }

    /* JADX INFO: renamed from: im.uwrkaxlmjj.ui.PassportActivity$1ValueToSend, reason: invalid class name */
    class C1ValueToSend {
        boolean selfie_required;
        boolean translation_required;
        TLRPC.TL_secureValue value;

        public C1ValueToSend(TLRPC.TL_secureValue v, boolean s, boolean t) {
            this.value = v;
            this.selfie_required = s;
            this.translation_required = t;
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:106:0x02df  */
    /* JADX WARN: Removed duplicated region for block: B:151:0x0179 A[EXC_TOP_SPLITTER, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:81:0x01ef  */
    /* JADX WARN: Removed duplicated region for block: B:84:0x01fb A[Catch: Exception -> 0x0223, TRY_ENTER, TRY_LEAVE, TryCatch #9 {Exception -> 0x0223, blocks: (B:72:0x0197, B:77:0x01d6, B:84:0x01fb, B:90:0x022e, B:93:0x0259, B:95:0x025f), top: B:155:0x0197 }] */
    /* JADX WARN: Removed duplicated region for block: B:90:0x022e A[Catch: Exception -> 0x0223, TRY_ENTER, TRY_LEAVE, TryCatch #9 {Exception -> 0x0223, blocks: (B:72:0x0197, B:77:0x01d6, B:84:0x01fb, B:90:0x022e, B:93:0x0259, B:95:0x025f), top: B:155:0x0197 }] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public /* synthetic */ void lambda$createRequestInterface$16$PassportActivity(android.view.View r22) {
        /*
            Method dump skipped, instruction units count: 957
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.ui.PassportActivity.lambda$createRequestInterface$16$PassportActivity(android.view.View):void");
    }

    public /* synthetic */ void lambda$null$15$PassportActivity(TLObject response, final TLRPC.TL_error error) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PassportActivity$fwtYnjABENq0ya_v4Jvaj8negwE
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$14$PassportActivity(error);
            }
        });
    }

    public /* synthetic */ void lambda$null$14$PassportActivity(TLRPC.TL_error error) {
        if (error == null) {
            this.ignoreOnFailure = true;
            callCallback(true);
            finishFragment();
        } else {
            showEditDoneProgress(false, false);
            if ("APP_VERSION_OUTDATED".equals(error.text)) {
                AlertsCreator.showUpdateAppAlert(getParentActivity(), LocaleController.getString("UpdateAppAlert", R.string.UpdateAppAlert), true);
            } else {
                showAlertWithText(LocaleController.getString("AppName", R.string.AppName), error.text);
            }
        }
    }

    private void createManageInterface(Context context) {
        ArrayList<TLRPC.TL_secureRequiredType> documentTypes;
        TLRPC.TL_secureRequiredType requiredType;
        boolean documentOnly;
        this.actionBar.setTitle(LocaleController.getString("AppPassport", R.string.AppPassport));
        this.actionBar.createMenu().addItem(1, R.drawable.profile_info);
        HeaderCell headerCell = new HeaderCell(context);
        this.headerCell = headerCell;
        headerCell.setText(LocaleController.getString("PassportProvidedInformation", R.string.PassportProvidedInformation));
        this.headerCell.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
        this.linearLayout2.addView(this.headerCell, LayoutHelper.createLinear(-1, -2));
        ShadowSectionCell shadowSectionCell = new ShadowSectionCell(context);
        this.sectionCell = shadowSectionCell;
        shadowSectionCell.setBackgroundDrawable(Theme.getThemedDrawable(context, R.drawable.greydivider, Theme.key_windowBackgroundGrayShadow));
        this.linearLayout2.addView(this.sectionCell, LayoutHelper.createLinear(-1, -2));
        TextSettingsCell textSettingsCell = new TextSettingsCell(context);
        this.addDocumentCell = textSettingsCell;
        textSettingsCell.setBackgroundDrawable(Theme.getSelectorDrawable(true));
        this.addDocumentCell.setText(LocaleController.getString("PassportNoDocumentsAdd", R.string.PassportNoDocumentsAdd), true);
        this.linearLayout2.addView(this.addDocumentCell, LayoutHelper.createLinear(-1, -2));
        this.addDocumentCell.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PassportActivity$-Qq8-DQ6j1w9KnSfi3tajoBk2hg
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                this.f$0.lambda$createManageInterface$17$PassportActivity(view);
            }
        });
        TextSettingsCell textSettingsCell2 = new TextSettingsCell(context);
        this.deletePassportCell = textSettingsCell2;
        textSettingsCell2.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteRedText3));
        this.deletePassportCell.setBackgroundDrawable(Theme.getSelectorDrawable(true));
        this.deletePassportCell.setText(LocaleController.getString("AppPassportDelete", R.string.AppPassportDelete), false);
        this.linearLayout2.addView(this.deletePassportCell, LayoutHelper.createLinear(-1, -2));
        this.deletePassportCell.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PassportActivity$hApLXLvpT5dFrlFShP51P8aSqE8
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                this.f$0.lambda$createManageInterface$21$PassportActivity(view);
            }
        });
        ShadowSectionCell shadowSectionCell2 = new ShadowSectionCell(context);
        this.addDocumentSectionCell = shadowSectionCell2;
        shadowSectionCell2.setBackgroundDrawable(Theme.getThemedDrawable(context, R.drawable.greydivider_bottom, Theme.key_windowBackgroundGrayShadow));
        this.linearLayout2.addView(this.addDocumentSectionCell, LayoutHelper.createLinear(-1, -2));
        LinearLayout linearLayout = new LinearLayout(context);
        this.emptyLayout = linearLayout;
        linearLayout.setOrientation(1);
        this.emptyLayout.setGravity(17);
        this.emptyLayout.setBackgroundDrawable(Theme.getThemedDrawable(context, R.drawable.greydivider_bottom, Theme.key_windowBackgroundGrayShadow));
        if (AndroidUtilities.isTablet()) {
            this.linearLayout2.addView(this.emptyLayout, new LinearLayout.LayoutParams(-1, AndroidUtilities.dp(528.0f) - ActionBar.getCurrentActionBarHeight()));
        } else {
            this.linearLayout2.addView(this.emptyLayout, new LinearLayout.LayoutParams(-1, AndroidUtilities.displaySize.y - ActionBar.getCurrentActionBarHeight()));
        }
        ImageView imageView = new ImageView(context);
        this.emptyImageView = imageView;
        imageView.setImageResource(R.drawable.no_passport);
        this.emptyImageView.setColorFilter(new PorterDuffColorFilter(Theme.getColor(Theme.key_sessions_devicesImage), PorterDuff.Mode.MULTIPLY));
        this.emptyLayout.addView(this.emptyImageView, LayoutHelper.createLinear(-2, -2));
        TextView textView = new TextView(context);
        this.emptyTextView1 = textView;
        textView.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteGrayText2));
        this.emptyTextView1.setGravity(17);
        this.emptyTextView1.setTextSize(1, 15.0f);
        this.emptyTextView1.setTypeface(AndroidUtilities.getTypeface("fonts/rmedium.ttf"));
        this.emptyTextView1.setText(LocaleController.getString("PassportNoDocuments", R.string.PassportNoDocuments));
        this.emptyLayout.addView(this.emptyTextView1, LayoutHelper.createLinear(-2, -2, 17, 0, 16, 0, 0));
        TextView textView2 = new TextView(context);
        this.emptyTextView2 = textView2;
        textView2.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteGrayText2));
        this.emptyTextView2.setGravity(17);
        this.emptyTextView2.setTextSize(1, 14.0f);
        this.emptyTextView2.setPadding(AndroidUtilities.dp(20.0f), 0, AndroidUtilities.dp(20.0f), 0);
        this.emptyTextView2.setText(LocaleController.getString("PassportNoDocumentsInfo", R.string.PassportNoDocumentsInfo));
        this.emptyLayout.addView(this.emptyTextView2, LayoutHelper.createLinear(-2, -2, 17, 0, 14, 0, 0));
        TextView textView3 = new TextView(context);
        this.emptyTextView3 = textView3;
        textView3.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteBlueText4));
        this.emptyTextView3.setGravity(17);
        this.emptyTextView3.setTextSize(1, 15.0f);
        this.emptyTextView3.setTypeface(AndroidUtilities.getTypeface("fonts/rmedium.ttf"));
        this.emptyTextView3.setGravity(17);
        this.emptyTextView3.setText(LocaleController.getString("PassportNoDocumentsAdd", R.string.PassportNoDocumentsAdd).toUpperCase());
        this.emptyLayout.addView(this.emptyTextView3, LayoutHelper.createLinear(-2, 30, 17, 0, 16, 0, 0));
        this.emptyTextView3.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PassportActivity$ieaP7YbOin32g8ULnzNVSqUEuA0
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                this.f$0.lambda$createManageInterface$22$PassportActivity(view);
            }
        });
        int size = this.currentForm.values.size();
        int a = 0;
        while (a < size) {
            TLRPC.TL_secureValue value = this.currentForm.values.get(a);
            if (!isPersonalDocument(value.type)) {
                if (isAddressDocument(value.type)) {
                    ArrayList<TLRPC.TL_secureRequiredType> documentTypes2 = new ArrayList<>();
                    TLRPC.TL_secureRequiredType requiredType2 = new TLRPC.TL_secureRequiredType();
                    requiredType2.type = value.type;
                    requiredType2.translation_required = true;
                    documentTypes2.add(requiredType2);
                    TLRPC.TL_secureRequiredType requiredType3 = new TLRPC.TL_secureRequiredType();
                    requiredType3.type = new TLRPC.TL_secureValueTypeAddress();
                    documentTypes = documentTypes2;
                    requiredType = requiredType3;
                    documentOnly = true;
                } else {
                    TLRPC.TL_secureRequiredType requiredType4 = new TLRPC.TL_secureRequiredType();
                    requiredType4.type = value.type;
                    documentTypes = null;
                    requiredType = requiredType4;
                    documentOnly = false;
                }
            } else {
                ArrayList<TLRPC.TL_secureRequiredType> documentTypes3 = new ArrayList<>();
                TLRPC.TL_secureRequiredType requiredType5 = new TLRPC.TL_secureRequiredType();
                requiredType5.type = value.type;
                requiredType5.selfie_required = true;
                requiredType5.translation_required = true;
                documentTypes3.add(requiredType5);
                TLRPC.TL_secureRequiredType requiredType6 = new TLRPC.TL_secureRequiredType();
                requiredType6.type = new TLRPC.TL_secureValueTypePersonalDetails();
                documentTypes = documentTypes3;
                requiredType = requiredType6;
                documentOnly = true;
            }
            addField(context, requiredType, documentTypes, documentOnly, a == size + (-1));
            a++;
        }
        updateManageVisibility();
    }

    public /* synthetic */ void lambda$createManageInterface$17$PassportActivity(View v) {
        openAddDocumentAlert();
    }

    public /* synthetic */ void lambda$createManageInterface$21$PassportActivity(View v) {
        AlertDialog.Builder builder = new AlertDialog.Builder(getParentActivity());
        builder.setPositiveButton(LocaleController.getString("OK", R.string.OK), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PassportActivity$APOxVbuZkBlaKdIar1JabPa1Tt0
            @Override // android.content.DialogInterface.OnClickListener
            public final void onClick(DialogInterface dialogInterface, int i) {
                this.f$0.lambda$null$20$PassportActivity(dialogInterface, i);
            }
        });
        builder.setNegativeButton(LocaleController.getString("Cancel", R.string.Cancel), null);
        builder.setTitle(LocaleController.getString("AppName", R.string.AppName));
        builder.setMessage(LocaleController.getString("AppPassportDeleteAlert", R.string.AppPassportDeleteAlert));
        showDialog(builder.create());
    }

    public /* synthetic */ void lambda$null$20$PassportActivity(DialogInterface dialog, int which) {
        TLRPC.TL_account_deleteSecureValue req = new TLRPC.TL_account_deleteSecureValue();
        for (int a = 0; a < this.currentForm.values.size(); a++) {
            req.types.add(this.currentForm.values.get(a).type);
        }
        needShowProgress();
        ConnectionsManager.getInstance(this.currentAccount).sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PassportActivity$W2xS9Z7Y8KN8X0iJrHBY9vszHpg
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                this.f$0.lambda$null$19$PassportActivity(tLObject, tL_error);
            }
        });
    }

    public /* synthetic */ void lambda$null$19$PassportActivity(TLObject response, TLRPC.TL_error error) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PassportActivity$UbMxKoAoS75eZXUtOaLAWVZrOXA
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$18$PassportActivity();
            }
        });
    }

    public /* synthetic */ void lambda$null$18$PassportActivity() {
        int a = 0;
        while (a < this.linearLayout2.getChildCount()) {
            View child = this.linearLayout2.getChildAt(a);
            if (child instanceof TextDetailSecureCell) {
                this.linearLayout2.removeView(child);
                a--;
            }
            a++;
        }
        needHideProgress();
        this.typesViews.clear();
        this.typesValues.clear();
        this.currentForm.values.clear();
        updateManageVisibility();
    }

    public /* synthetic */ void lambda$createManageInterface$22$PassportActivity(View v) {
        openAddDocumentAlert();
    }

    private boolean hasNotValueForType(Class<? extends TLRPC.SecureValueType> type) {
        int count = this.currentForm.values.size();
        for (int a = 0; a < count; a++) {
            if (this.currentForm.values.get(a).type.getClass() == type) {
                return false;
            }
        }
        return true;
    }

    private boolean hasUnfilledValues() {
        return hasNotValueForType(TLRPC.TL_secureValueTypePhone.class) || hasNotValueForType(TLRPC.TL_secureValueTypeEmail.class) || hasNotValueForType(TLRPC.TL_secureValueTypePersonalDetails.class) || hasNotValueForType(TLRPC.TL_secureValueTypePassport.class) || hasNotValueForType(TLRPC.TL_secureValueTypeInternalPassport.class) || hasNotValueForType(TLRPC.TL_secureValueTypeIdentityCard.class) || hasNotValueForType(TLRPC.TL_secureValueTypeDriverLicense.class) || hasNotValueForType(TLRPC.TL_secureValueTypeAddress.class) || hasNotValueForType(TLRPC.TL_secureValueTypeUtilityBill.class) || hasNotValueForType(TLRPC.TL_secureValueTypePassportRegistration.class) || hasNotValueForType(TLRPC.TL_secureValueTypeTemporaryRegistration.class) || hasNotValueForType(TLRPC.TL_secureValueTypeBankStatement.class) || hasNotValueForType(TLRPC.TL_secureValueTypeRentalAgreement.class);
    }

    private void openAddDocumentAlert() {
        ArrayList<CharSequence> values = new ArrayList<>();
        final ArrayList<Class<? extends TLRPC.SecureValueType>> types = new ArrayList<>();
        if (hasNotValueForType(TLRPC.TL_secureValueTypePhone.class)) {
            values.add(LocaleController.getString("ActionBotDocumentPhone", R.string.ActionBotDocumentPhone));
            types.add(TLRPC.TL_secureValueTypePhone.class);
        }
        if (hasNotValueForType(TLRPC.TL_secureValueTypeEmail.class)) {
            values.add(LocaleController.getString("ActionBotDocumentEmail", R.string.ActionBotDocumentEmail));
            types.add(TLRPC.TL_secureValueTypeEmail.class);
        }
        if (hasNotValueForType(TLRPC.TL_secureValueTypePersonalDetails.class)) {
            values.add(LocaleController.getString("ActionBotDocumentIdentity", R.string.ActionBotDocumentIdentity));
            types.add(TLRPC.TL_secureValueTypePersonalDetails.class);
        }
        if (hasNotValueForType(TLRPC.TL_secureValueTypePassport.class)) {
            values.add(LocaleController.getString("ActionBotDocumentPassport", R.string.ActionBotDocumentPassport));
            types.add(TLRPC.TL_secureValueTypePassport.class);
        }
        if (hasNotValueForType(TLRPC.TL_secureValueTypeInternalPassport.class)) {
            values.add(LocaleController.getString("ActionBotDocumentInternalPassport", R.string.ActionBotDocumentInternalPassport));
            types.add(TLRPC.TL_secureValueTypeInternalPassport.class);
        }
        if (hasNotValueForType(TLRPC.TL_secureValueTypePassportRegistration.class)) {
            values.add(LocaleController.getString("ActionBotDocumentPassportRegistration", R.string.ActionBotDocumentPassportRegistration));
            types.add(TLRPC.TL_secureValueTypePassportRegistration.class);
        }
        if (hasNotValueForType(TLRPC.TL_secureValueTypeTemporaryRegistration.class)) {
            values.add(LocaleController.getString("ActionBotDocumentTemporaryRegistration", R.string.ActionBotDocumentTemporaryRegistration));
            types.add(TLRPC.TL_secureValueTypeTemporaryRegistration.class);
        }
        if (hasNotValueForType(TLRPC.TL_secureValueTypeIdentityCard.class)) {
            values.add(LocaleController.getString("ActionBotDocumentIdentityCard", R.string.ActionBotDocumentIdentityCard));
            types.add(TLRPC.TL_secureValueTypeIdentityCard.class);
        }
        if (hasNotValueForType(TLRPC.TL_secureValueTypeDriverLicense.class)) {
            values.add(LocaleController.getString("ActionBotDocumentDriverLicence", R.string.ActionBotDocumentDriverLicence));
            types.add(TLRPC.TL_secureValueTypeDriverLicense.class);
        }
        if (hasNotValueForType(TLRPC.TL_secureValueTypeAddress.class)) {
            values.add(LocaleController.getString("ActionBotDocumentAddress", R.string.ActionBotDocumentAddress));
            types.add(TLRPC.TL_secureValueTypeAddress.class);
        }
        if (hasNotValueForType(TLRPC.TL_secureValueTypeUtilityBill.class)) {
            values.add(LocaleController.getString("ActionBotDocumentUtilityBill", R.string.ActionBotDocumentUtilityBill));
            types.add(TLRPC.TL_secureValueTypeUtilityBill.class);
        }
        if (hasNotValueForType(TLRPC.TL_secureValueTypeBankStatement.class)) {
            values.add(LocaleController.getString("ActionBotDocumentBankStatement", R.string.ActionBotDocumentBankStatement));
            types.add(TLRPC.TL_secureValueTypeBankStatement.class);
        }
        if (hasNotValueForType(TLRPC.TL_secureValueTypeRentalAgreement.class)) {
            values.add(LocaleController.getString("ActionBotDocumentRentalAgreement", R.string.ActionBotDocumentRentalAgreement));
            types.add(TLRPC.TL_secureValueTypeRentalAgreement.class);
        }
        if (getParentActivity() == null || values.isEmpty()) {
            return;
        }
        AlertDialog.Builder builder = new AlertDialog.Builder(getParentActivity());
        builder.setTitle(LocaleController.getString("PassportNoDocumentsAdd", R.string.PassportNoDocumentsAdd));
        builder.setItems((CharSequence[]) values.toArray(new CharSequence[0]), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PassportActivity$ZcWUVoK9k6TpUc4h2EtjKzC37T0
            @Override // android.content.DialogInterface.OnClickListener
            public final void onClick(DialogInterface dialogInterface, int i) {
                this.f$0.lambda$openAddDocumentAlert$23$PassportActivity(types, dialogInterface, i);
            }
        });
        showDialog(builder.create());
    }

    public /* synthetic */ void lambda$openAddDocumentAlert$23$PassportActivity(ArrayList types, DialogInterface dialog, int which) {
        TLRPC.TL_secureRequiredType requiredType = null;
        TLRPC.TL_secureRequiredType documentRequiredType = null;
        try {
            requiredType = new TLRPC.TL_secureRequiredType();
            requiredType.type = (TLRPC.SecureValueType) ((Class) types.get(which)).newInstance();
        } catch (Exception e) {
        }
        if (isPersonalDocument(requiredType.type)) {
            documentRequiredType = requiredType;
            documentRequiredType.selfie_required = true;
            documentRequiredType.translation_required = true;
            requiredType = new TLRPC.TL_secureRequiredType();
            requiredType.type = new TLRPC.TL_secureValueTypePersonalDetails();
        } else if (isAddressDocument(requiredType.type)) {
            documentRequiredType = requiredType;
            requiredType = new TLRPC.TL_secureRequiredType();
            requiredType.type = new TLRPC.TL_secureValueTypeAddress();
        }
        openTypeActivity(requiredType, documentRequiredType, new ArrayList<>(), documentRequiredType != null);
    }

    private void updateManageVisibility() {
        if (this.currentForm.values.isEmpty()) {
            this.emptyLayout.setVisibility(0);
            this.sectionCell.setVisibility(8);
            this.headerCell.setVisibility(8);
            this.addDocumentCell.setVisibility(8);
            this.deletePassportCell.setVisibility(8);
            this.addDocumentSectionCell.setVisibility(8);
            return;
        }
        this.emptyLayout.setVisibility(8);
        this.sectionCell.setVisibility(0);
        this.headerCell.setVisibility(0);
        this.deletePassportCell.setVisibility(0);
        this.addDocumentSectionCell.setVisibility(0);
        if (hasUnfilledValues()) {
            this.addDocumentCell.setVisibility(0);
        } else {
            this.addDocumentCell.setVisibility(8);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void callCallback(boolean success) {
        int i;
        int i2;
        if (!this.callbackCalled) {
            if (!TextUtils.isEmpty(this.currentCallbackUrl)) {
                if (success) {
                    Browser.openUrl(getParentActivity(), Uri.parse(this.currentCallbackUrl + "&tg_passport=success"));
                } else if (!this.ignoreOnFailure && ((i2 = this.currentActivityType) == 5 || i2 == 0)) {
                    Browser.openUrl(getParentActivity(), Uri.parse(this.currentCallbackUrl + "&tg_passport=cancel"));
                }
                this.callbackCalled = true;
                return;
            }
            if (this.needActivityResult) {
                if (success || (!this.ignoreOnFailure && ((i = this.currentActivityType) == 5 || i == 0))) {
                    getParentActivity().setResult(success ? -1 : 0);
                }
                this.callbackCalled = true;
            }
        }
    }

    private void createEmailInterface(Context context) {
        this.actionBar.setTitle(LocaleController.getString("PassportEmail", R.string.PassportEmail));
        if (!TextUtils.isEmpty(this.currentEmail)) {
            TextSettingsCell settingsCell1 = new TextSettingsCell(context);
            settingsCell1.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteBlueText4));
            settingsCell1.setBackgroundDrawable(Theme.getSelectorDrawable(true));
            settingsCell1.setText(LocaleController.formatString("PassportPhoneUseSame", R.string.PassportPhoneUseSame, this.currentEmail), false);
            this.linearLayout2.addView(settingsCell1, LayoutHelper.createLinear(-1, -2));
            settingsCell1.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PassportActivity$Ay2wad5dX0OHMOirKBJmsvAzkAg
                @Override // android.view.View.OnClickListener
                public final void onClick(View view) {
                    this.f$0.lambda$createEmailInterface$24$PassportActivity(view);
                }
            });
            TextInfoPrivacyCell textInfoPrivacyCell = new TextInfoPrivacyCell(context);
            this.bottomCell = textInfoPrivacyCell;
            textInfoPrivacyCell.setBackgroundDrawable(Theme.getThemedDrawable(context, R.drawable.greydivider_bottom, Theme.key_windowBackgroundGrayShadow));
            this.bottomCell.setText(LocaleController.getString("PassportPhoneUseSameEmailInfo", R.string.PassportPhoneUseSameEmailInfo));
            this.linearLayout2.addView(this.bottomCell, LayoutHelper.createLinear(-1, -2));
        }
        this.inputFields = new EditTextBoldCursor[1];
        for (int a = 0; a < 1; a++) {
            ViewGroup container = new FrameLayout(context);
            this.linearLayout2.addView(container, LayoutHelper.createLinear(-1, 50));
            container.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
            this.inputFields[a] = new EditTextBoldCursor(context);
            this.inputFields[a].setTag(Integer.valueOf(a));
            this.inputFields[a].setTextSize(1, 16.0f);
            this.inputFields[a].setHintTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteHintText));
            this.inputFields[a].setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteBlackText));
            this.inputFields[a].setBackgroundDrawable(null);
            this.inputFields[a].setCursorColor(Theme.getColor(Theme.key_windowBackgroundWhiteBlackText));
            this.inputFields[a].setCursorSize(AndroidUtilities.dp(20.0f));
            this.inputFields[a].setCursorWidth(1.5f);
            this.inputFields[a].setInputType(33);
            this.inputFields[a].setImeOptions(268435462);
            this.inputFields[a].setHint(LocaleController.getString("PaymentShippingEmailPlaceholder", R.string.PaymentShippingEmailPlaceholder));
            TLRPC.TL_secureValue tL_secureValue = this.currentTypeValue;
            if (tL_secureValue != null && (tL_secureValue.plain_data instanceof TLRPC.TL_securePlainEmail)) {
                TLRPC.TL_securePlainEmail securePlainEmail = (TLRPC.TL_securePlainEmail) this.currentTypeValue.plain_data;
                if (!TextUtils.isEmpty(securePlainEmail.email)) {
                    this.inputFields[a].setText(securePlainEmail.email);
                }
            }
            EditTextBoldCursor[] editTextBoldCursorArr = this.inputFields;
            editTextBoldCursorArr[a].setSelection(editTextBoldCursorArr[a].length());
            this.inputFields[a].setPadding(0, 0, 0, AndroidUtilities.dp(6.0f));
            this.inputFields[a].setGravity(LocaleController.isRTL ? 5 : 3);
            container.addView(this.inputFields[a], LayoutHelper.createFrame(-1.0f, -2.0f, 51, 21.0f, 12.0f, 21.0f, 6.0f));
            this.inputFields[a].setOnEditorActionListener(new TextView.OnEditorActionListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PassportActivity$z8sntNaLYlCK2hI25QrcCdMTTOI
                @Override // android.widget.TextView.OnEditorActionListener
                public final boolean onEditorAction(TextView textView, int i, KeyEvent keyEvent) {
                    return this.f$0.lambda$createEmailInterface$25$PassportActivity(textView, i, keyEvent);
                }
            });
        }
        TextInfoPrivacyCell textInfoPrivacyCell2 = new TextInfoPrivacyCell(context);
        this.bottomCell = textInfoPrivacyCell2;
        textInfoPrivacyCell2.setBackgroundDrawable(Theme.getThemedDrawable(context, R.drawable.greydivider_bottom, Theme.key_windowBackgroundGrayShadow));
        this.bottomCell.setText(LocaleController.getString("PassportEmailUploadInfo", R.string.PassportEmailUploadInfo));
        this.linearLayout2.addView(this.bottomCell, LayoutHelper.createLinear(-1, -2));
    }

    public /* synthetic */ void lambda$createEmailInterface$24$PassportActivity(View v) {
        this.useCurrentValue = true;
        this.doneItem.callOnClick();
        this.useCurrentValue = false;
    }

    public /* synthetic */ boolean lambda$createEmailInterface$25$PassportActivity(TextView textView, int i, KeyEvent keyEvent) {
        if (i == 6 || i == 5) {
            this.doneItem.callOnClick();
            return true;
        }
        return false;
    }

    /* JADX WARN: Can't wrap try/catch for region: R(15:0|2|(2:66|3)|(12:4|(3:6|(2:8|69)(1:70)|9)(1:68)|14|(11:(1:17)(1:18)|19|(1:21)(1:(1:23)(1:24))|25|(1:27)(2:28|(1:30)(1:31))|32|(1:34)(1:(1:36)(3:37|(1:40)|41))|42|(1:44)|(2:46|72)(1:73)|47)|71|48|64|49|(2:51|52)|(2:59|(1:61))|62|63)|10|14|(0)|71|48|64|49|(0)|(3:57|59|(0))|62|63) */
    /* JADX WARN: Code restructure failed: missing block: B:54:0x0396, code lost:
    
        r0 = move-exception;
     */
    /* JADX WARN: Code restructure failed: missing block: B:55:0x0397, code lost:
    
        im.uwrkaxlmjj.messenger.FileLog.e(r0);
     */
    /* JADX WARN: Removed duplicated region for block: B:16:0x013b  */
    /* JADX WARN: Removed duplicated region for block: B:51:0x038c A[Catch: Exception -> 0x0396, TRY_LEAVE, TryCatch #0 {Exception -> 0x0396, blocks: (B:49:0x0380, B:51:0x038c), top: B:64:0x0380 }] */
    /* JADX WARN: Removed duplicated region for block: B:61:0x03af  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    private void createPhoneInterface(android.content.Context r25) {
        /*
            Method dump skipped, instruction units count: 1004
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.ui.PassportActivity.createPhoneInterface(android.content.Context):void");
    }

    public /* synthetic */ void lambda$createPhoneInterface$26$PassportActivity(View v) {
        this.useCurrentValue = true;
        this.doneItem.callOnClick();
        this.useCurrentValue = false;
    }

    public /* synthetic */ boolean lambda$createPhoneInterface$29$PassportActivity(View v, MotionEvent event) {
        if (getParentActivity() == null) {
            return false;
        }
        if (event.getAction() == 1) {
            CountrySelectActivity fragment = new CountrySelectActivity(false);
            fragment.setCountrySelectActivityDelegate(new CountrySelectActivity.CountrySelectActivityDelegate() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PassportActivity$t241rSpMu9SoOyodVoljDzkdcQ0
                @Override // im.uwrkaxlmjj.ui.CountrySelectActivity.CountrySelectActivityDelegate
                public final void didSelectCountry(CountrySelectActivity.Country country) {
                    this.f$0.lambda$null$28$PassportActivity(country);
                }
            });
            presentFragment(fragment);
        }
        return true;
    }

    public /* synthetic */ void lambda$null$28$PassportActivity(CountrySelectActivity.Country country) {
        if (country != null) {
            this.inputFields[0].setText(country.name);
            int index = this.countriesArray.indexOf(country.name);
            if (index != -1) {
                this.ignoreOnTextChange = true;
                String code = this.countriesMap.get(country.name);
                this.inputFields[1].setText(code);
                String hint = this.phoneFormatMap.get(code);
                this.inputFields[2].setHintText(hint != null ? hint.replace('X', Typography.ndash) : null);
                this.ignoreOnTextChange = false;
            }
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PassportActivity$e3ulf5utbUcd02MNHdiVz5rnp54
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$null$27$PassportActivity();
                }
            }, 300L);
            this.inputFields[2].requestFocus();
            EditTextBoldCursor[] editTextBoldCursorArr = this.inputFields;
            editTextBoldCursorArr[2].setSelection(editTextBoldCursorArr[2].length());
        }
    }

    public /* synthetic */ void lambda$null$27$PassportActivity() {
        AndroidUtilities.showKeyboard(this.inputFields[2]);
    }

    public /* synthetic */ boolean lambda$createPhoneInterface$30$PassportActivity(TextView textView, int i, KeyEvent keyEvent) {
        if (i == 5) {
            this.inputFields[2].requestFocus();
            return true;
        }
        if (i == 6) {
            this.doneItem.callOnClick();
            return true;
        }
        return false;
    }

    public /* synthetic */ boolean lambda$createPhoneInterface$31$PassportActivity(View v, int keyCode, KeyEvent event) {
        if (keyCode == 67 && this.inputFields[2].length() == 0) {
            this.inputFields[1].requestFocus();
            EditTextBoldCursor[] editTextBoldCursorArr = this.inputFields;
            editTextBoldCursorArr[1].setSelection(editTextBoldCursorArr[1].length());
            this.inputFields[1].dispatchKeyEvent(event);
            return true;
        }
        return false;
    }

    /* JADX WARN: Removed duplicated region for block: B:13:0x007f  */
    /* JADX WARN: Removed duplicated region for block: B:143:0x05eb  */
    /* JADX WARN: Removed duplicated region for block: B:146:0x061b  */
    /* JADX WARN: Removed duplicated region for block: B:147:0x0628  */
    /* JADX WARN: Removed duplicated region for block: B:81:0x0358  */
    /* JADX WARN: Removed duplicated region for block: B:85:0x0398  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    private void createAddressInterface(android.content.Context r25) {
        /*
            Method dump skipped, instruction units count: 1667
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.ui.PassportActivity.createAddressInterface(android.content.Context):void");
    }

    public /* synthetic */ void lambda$createAddressInterface$32$PassportActivity(View v) {
        this.uploadingFileType = 0;
        openAttachMenu();
    }

    public /* synthetic */ void lambda$createAddressInterface$33$PassportActivity(View v) {
        this.uploadingFileType = 4;
        openAttachMenu();
    }

    public /* synthetic */ boolean lambda$createAddressInterface$35$PassportActivity(View v, MotionEvent event) {
        if (getParentActivity() == null) {
            return false;
        }
        if (event.getAction() == 1) {
            CountrySelectActivity fragment = new CountrySelectActivity(false);
            fragment.setCountrySelectActivityDelegate(new CountrySelectActivity.CountrySelectActivityDelegate() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PassportActivity$j0TRF7f8QbKjdv-5AHpQttlGhvg
                @Override // im.uwrkaxlmjj.ui.CountrySelectActivity.CountrySelectActivityDelegate
                public final void didSelectCountry(CountrySelectActivity.Country country) {
                    this.f$0.lambda$null$34$PassportActivity(country);
                }
            });
            presentFragment(fragment);
        }
        return true;
    }

    public /* synthetic */ void lambda$null$34$PassportActivity(CountrySelectActivity.Country country) {
        if (country != null) {
            this.inputFields[5].setText(country.name);
            this.currentCitizeship = country.shortname;
        }
    }

    public /* synthetic */ boolean lambda$createAddressInterface$36$PassportActivity(TextView textView, int i, KeyEvent keyEvent) {
        if (i == 5) {
            int num = ((Integer) textView.getTag()).intValue() + 1;
            EditTextBoldCursor[] editTextBoldCursorArr = this.inputFields;
            if (num < editTextBoldCursorArr.length) {
                if (editTextBoldCursorArr[num].isFocusable()) {
                    this.inputFields[num].requestFocus();
                } else {
                    this.inputFields[num].dispatchTouchEvent(MotionEvent.obtain(0L, 0L, 1, 0.0f, 0.0f, 0));
                    textView.clearFocus();
                    AndroidUtilities.hideKeyboard(textView);
                }
            }
            return true;
        }
        return false;
    }

    public /* synthetic */ void lambda$createAddressInterface$37$PassportActivity(View v) {
        createDocumentDeleteAlert();
    }

    private void createDocumentDeleteAlert() {
        final boolean[] checks = {true};
        AlertDialog.Builder builder = new AlertDialog.Builder(getParentActivity());
        builder.setPositiveButton(LocaleController.getString("OK", R.string.OK), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PassportActivity$6dzJyINNu8wVup5BzEFYQGxJhrU
            @Override // android.content.DialogInterface.OnClickListener
            public final void onClick(DialogInterface dialogInterface, int i) {
                this.f$0.lambda$createDocumentDeleteAlert$38$PassportActivity(checks, dialogInterface, i);
            }
        });
        builder.setNegativeButton(LocaleController.getString("Cancel", R.string.Cancel), null);
        builder.setTitle(LocaleController.getString("AppName", R.string.AppName));
        if (this.documentOnly && this.currentDocumentsType == null && (this.currentType.type instanceof TLRPC.TL_secureValueTypeAddress)) {
            builder.setMessage(LocaleController.getString("PassportDeleteAddressAlert", R.string.PassportDeleteAddressAlert));
        } else if (this.documentOnly && this.currentDocumentsType == null && (this.currentType.type instanceof TLRPC.TL_secureValueTypePersonalDetails)) {
            builder.setMessage(LocaleController.getString("PassportDeletePersonalAlert", R.string.PassportDeletePersonalAlert));
        } else {
            builder.setMessage(LocaleController.getString("PassportDeleteDocumentAlert", R.string.PassportDeleteDocumentAlert));
        }
        if (!this.documentOnly && this.currentDocumentsType != null) {
            FrameLayout frameLayout = new FrameLayout(getParentActivity());
            CheckBoxCell cell = new CheckBoxCell(getParentActivity(), 1);
            cell.setBackgroundDrawable(Theme.getSelectorDrawable(false));
            if (this.currentType.type instanceof TLRPC.TL_secureValueTypeAddress) {
                cell.setText(LocaleController.getString("PassportDeleteDocumentAddress", R.string.PassportDeleteDocumentAddress), "", true, false);
            } else if (this.currentType.type instanceof TLRPC.TL_secureValueTypePersonalDetails) {
                cell.setText(LocaleController.getString("PassportDeleteDocumentPersonal", R.string.PassportDeleteDocumentPersonal), "", true, false);
            }
            cell.setPadding(LocaleController.isRTL ? AndroidUtilities.dp(16.0f) : AndroidUtilities.dp(8.0f), 0, LocaleController.isRTL ? AndroidUtilities.dp(8.0f) : AndroidUtilities.dp(16.0f), 0);
            frameLayout.addView(cell, LayoutHelper.createFrame(-1, 48, 51));
            cell.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PassportActivity$T06ZRWTd2VZqpW7xOkZqZ1BWJVw
                @Override // android.view.View.OnClickListener
                public final void onClick(View view) {
                    PassportActivity.lambda$createDocumentDeleteAlert$39(checks, view);
                }
            });
            builder.setView(frameLayout);
        }
        showDialog(builder.create());
    }

    public /* synthetic */ void lambda$createDocumentDeleteAlert$38$PassportActivity(boolean[] checks, DialogInterface dialog, int which) {
        if (!this.documentOnly) {
            this.currentValues.clear();
        }
        this.currentDocumentValues.clear();
        this.delegate.deleteValue(this.currentType, this.currentDocumentsType, this.availableDocumentTypes, checks[0], null, null);
        finishFragment();
    }

    static /* synthetic */ void lambda$createDocumentDeleteAlert$39(boolean[] checks, View v) {
        if (!v.isEnabled()) {
            return;
        }
        CheckBoxCell cell1 = (CheckBoxCell) v;
        checks[0] = !checks[0];
        cell1.setChecked(checks[0], true);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void onFieldError(View field) {
        if (field == null) {
            return;
        }
        Vibrator v = (Vibrator) getParentActivity().getSystemService("vibrator");
        if (v != null) {
            v.vibrate(200L);
        }
        AndroidUtilities.shakeView(field, 2.0f, 0);
        scrollToField(field);
    }

    private void scrollToField(View field) {
        while (field != null && this.linearLayout2.indexOfChild(field) < 0) {
            field = (View) field.getParent();
        }
        if (field != null) {
            this.scrollView.smoothScrollTo(0, field.getTop() - ((this.scrollView.getMeasuredHeight() - field.getMeasuredHeight()) / 2));
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public String getDocumentHash(SecureDocument document) {
        if (document != null) {
            if (document.secureFile != null && document.secureFile.file_hash != null) {
                return Base64.encodeToString(document.secureFile.file_hash, 2);
            }
            if (document.fileHash != null) {
                return Base64.encodeToString(document.fileHash, 2);
            }
            return "";
        }
        return "";
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void checkFieldForError(EditTextBoldCursor field, String key, Editable s, boolean document) {
        String value;
        String value2;
        String value3;
        HashMap<String, String> map = this.errorsValues;
        if (map != null && (value = map.get(key)) != null && TextUtils.equals(value, s)) {
            HashMap<String, String> map2 = this.fieldsErrors;
            if (map2 != null && (value3 = map2.get(key)) != null) {
                field.setErrorText(value3);
            } else {
                HashMap<String, String> map3 = this.documentsErrors;
                if (map3 != null && (value2 = map3.get(key)) != null) {
                    field.setErrorText(value2);
                }
            }
        } else {
            field.setErrorText(null);
        }
        String errorKey = document ? "error_document_all" : "error_all";
        HashMap<String, String> map4 = this.errorsValues;
        if (map4 != null && map4.containsKey(errorKey)) {
            this.errorsValues.remove(errorKey);
            checkTopErrorCell(false);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* JADX WARN: Removed duplicated region for block: B:219:0x02d2 A[SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:223:0x02d8 A[SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public boolean checkFieldsForError() {
        /*
            Method dump skipped, instruction units count: 760
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.ui.PassportActivity.checkFieldsForError():boolean");
    }

    /* JADX WARN: Removed duplicated region for block: B:112:0x060e  */
    /* JADX WARN: Removed duplicated region for block: B:118:0x0622  */
    /* JADX WARN: Removed duplicated region for block: B:121:0x063e  */
    /* JADX WARN: Removed duplicated region for block: B:122:0x0640  */
    /* JADX WARN: Removed duplicated region for block: B:13:0x007f  */
    /* JADX WARN: Removed duplicated region for block: B:186:0x0671 A[SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:45:0x02e9  */
    /* JADX WARN: Removed duplicated region for block: B:51:0x035a  */
    /* JADX WARN: Removed duplicated region for block: B:52:0x0367  */
    /* JADX WARN: Removed duplicated region for block: B:55:0x038c  */
    /* JADX WARN: Removed duplicated region for block: B:56:0x038f  */
    /* JADX WARN: Removed duplicated region for block: B:60:0x03a0  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    private void createIdentityInterface(final android.content.Context r27) {
        /*
            Method dump skipped, instruction units count: 2316
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.ui.PassportActivity.createIdentityInterface(android.content.Context):void");
    }

    public /* synthetic */ void lambda$createIdentityInterface$40$PassportActivity(View v) {
        this.uploadingFileType = 2;
        openAttachMenu();
    }

    public /* synthetic */ void lambda$createIdentityInterface$41$PassportActivity(View v) {
        this.uploadingFileType = 3;
        openAttachMenu();
    }

    public /* synthetic */ void lambda$createIdentityInterface$42$PassportActivity(View v) {
        this.uploadingFileType = 1;
        openAttachMenu();
    }

    public /* synthetic */ void lambda$createIdentityInterface$43$PassportActivity(View v) {
        this.uploadingFileType = 4;
        openAttachMenu();
    }

    public /* synthetic */ void lambda$createIdentityInterface$45$PassportActivity(View v) {
        if (Build.VERSION.SDK_INT >= 23 && getParentActivity().checkSelfPermission("android.permission.CAMERA") != 0) {
            getParentActivity().requestPermissions(new String[]{"android.permission.CAMERA"}, 22);
            return;
        }
        MrzCameraActivity fragment = new MrzCameraActivity();
        fragment.setDelegate(new MrzCameraActivity.MrzCameraActivityDelegate() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PassportActivity$JIM0FTjSqPFUU6kjN2pkn8Le_PQ
            @Override // im.uwrkaxlmjj.ui.MrzCameraActivity.MrzCameraActivityDelegate
            public final void didFindMrzInfo(MrzRecognizer.Result result) {
                this.f$0.lambda$null$44$PassportActivity(result);
            }
        });
        presentFragment(fragment);
    }

    public /* synthetic */ void lambda$null$44$PassportActivity(MrzRecognizer.Result result) {
        if (!TextUtils.isEmpty(result.firstName)) {
            this.inputFields[0].setText(result.firstName);
        }
        if (!TextUtils.isEmpty(result.middleName)) {
            this.inputFields[1].setText(result.middleName);
        }
        if (!TextUtils.isEmpty(result.lastName)) {
            this.inputFields[2].setText(result.lastName);
        }
        if (result.gender != 0) {
            int i = result.gender;
            if (i == 1) {
                this.currentGender = "male";
                this.inputFields[4].setText(LocaleController.getString("PassportMale", R.string.PassportMale));
            } else if (i == 2) {
                this.currentGender = "female";
                this.inputFields[4].setText(LocaleController.getString("PassportFemale", R.string.PassportFemale));
            }
        }
        if (!TextUtils.isEmpty(result.nationality)) {
            String str = result.nationality;
            this.currentCitizeship = str;
            String country = this.languageMap.get(str);
            if (country != null) {
                this.inputFields[5].setText(country);
            }
        }
        if (!TextUtils.isEmpty(result.issuingCountry)) {
            String str2 = result.issuingCountry;
            this.currentResidence = str2;
            String country2 = this.languageMap.get(str2);
            if (country2 != null) {
                this.inputFields[6].setText(country2);
            }
        }
        if (result.birthDay > 0 && result.birthMonth > 0 && result.birthYear > 0) {
            this.inputFields[3].setText(String.format(Locale.US, "%02d.%02d.%d", Integer.valueOf(result.birthDay), Integer.valueOf(result.birthMonth), Integer.valueOf(result.birthYear)));
        }
    }

    public /* synthetic */ boolean lambda$createIdentityInterface$47$PassportActivity(final View v, MotionEvent event) {
        if (getParentActivity() == null) {
            return false;
        }
        if (event.getAction() == 1) {
            CountrySelectActivity fragment = new CountrySelectActivity(false);
            fragment.setCountrySelectActivityDelegate(new CountrySelectActivity.CountrySelectActivityDelegate() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PassportActivity$fggZ6pch4J0XqqFX7CMqM21j2TI
                @Override // im.uwrkaxlmjj.ui.CountrySelectActivity.CountrySelectActivityDelegate
                public final void didSelectCountry(CountrySelectActivity.Country country) {
                    this.f$0.lambda$null$46$PassportActivity(v, country);
                }
            });
            presentFragment(fragment);
        }
        return true;
    }

    public /* synthetic */ void lambda$null$46$PassportActivity(View v, CountrySelectActivity.Country country) {
        if (country != null) {
            int field12 = ((Integer) v.getTag()).intValue();
            EditTextBoldCursor editText = this.inputFields[field12];
            if (field12 == 5) {
                this.currentCitizeship = country.shortname;
            } else {
                this.currentResidence = country.shortname;
            }
            editText.setText(country.name + "");
        }
    }

    public /* synthetic */ boolean lambda$createIdentityInterface$50$PassportActivity(Context context, View v, MotionEvent event) {
        String title;
        int minYear;
        int maxYear;
        int currentYearDiff;
        int selectedDay;
        int selectedMonth;
        int selectedYear;
        if (getParentActivity() == null) {
            return false;
        }
        if (event.getAction() == 1) {
            Calendar calendar = Calendar.getInstance();
            calendar.get(1);
            calendar.get(2);
            calendar.get(5);
            try {
                final EditTextBoldCursor field1 = (EditTextBoldCursor) v;
                final int num = ((Integer) field1.getTag()).intValue();
                if (num == 8) {
                    title = LocaleController.getString("PassportSelectExpiredDate", R.string.PassportSelectExpiredDate);
                    minYear = 0;
                    maxYear = 20;
                    currentYearDiff = 0;
                } else {
                    title = LocaleController.getString("PassportSelectBithdayDate", R.string.PassportSelectBithdayDate);
                    minYear = -120;
                    maxYear = 0;
                    currentYearDiff = -18;
                }
                String[] args = field1.getText().toString().split("\\.");
                if (args.length != 3) {
                    selectedDay = -1;
                    selectedMonth = -1;
                    selectedYear = -1;
                } else {
                    int selectedDay2 = Utilities.parseInt(args[0]).intValue();
                    int selectedMonth2 = Utilities.parseInt(args[1]).intValue();
                    int selectedYear2 = Utilities.parseInt(args[2]).intValue();
                    selectedDay = selectedDay2;
                    selectedMonth = selectedMonth2;
                    selectedYear = selectedYear2;
                }
                AlertDialog.Builder builder = AlertsCreator.createDatePickerDialog(context, minYear, maxYear, currentYearDiff, selectedDay, selectedMonth, selectedYear, title, num == 8, new AlertsCreator.DatePickerDelegate() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PassportActivity$Or5Taq0k-EBbzJjQTHVmRiZSc4U
                    @Override // im.uwrkaxlmjj.ui.components.AlertsCreator.DatePickerDelegate
                    public final void didSelectDate(int i, int i2, int i3) {
                        this.f$0.lambda$null$48$PassportActivity(num, field1, i, i2, i3);
                    }
                });
                if (num == 8) {
                    builder.setNegativeButton(LocaleController.getString("PassportSelectNotExpire", R.string.PassportSelectNotExpire), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PassportActivity$fZExM618h6A80rp-CLYAfqT0FpE
                        @Override // android.content.DialogInterface.OnClickListener
                        public final void onClick(DialogInterface dialogInterface, int i) {
                            this.f$0.lambda$null$49$PassportActivity(field1, dialogInterface, i);
                        }
                    });
                }
                showDialog(builder.create());
                return true;
            } catch (Exception e) {
                FileLog.e(e);
                return true;
            }
        }
        return true;
    }

    public /* synthetic */ void lambda$null$48$PassportActivity(int num, EditTextBoldCursor field1, int year1, int month, int dayOfMonth1) {
        if (num == 8) {
            int[] iArr = this.currentExpireDate;
            iArr[0] = year1;
            iArr[1] = month + 1;
            iArr[2] = dayOfMonth1;
        }
        field1.setText(String.format(Locale.US, "%02d.%02d.%d", Integer.valueOf(dayOfMonth1), Integer.valueOf(month + 1), Integer.valueOf(year1)));
    }

    public /* synthetic */ void lambda$null$49$PassportActivity(EditTextBoldCursor field1, DialogInterface dialog, int which) {
        int[] iArr = this.currentExpireDate;
        iArr[2] = 0;
        iArr[1] = 0;
        iArr[0] = 0;
        field1.setText(LocaleController.getString("PassportNoExpireDate", R.string.PassportNoExpireDate));
    }

    public /* synthetic */ boolean lambda$createIdentityInterface$52$PassportActivity(View v, MotionEvent event) {
        if (getParentActivity() == null) {
            return false;
        }
        if (event.getAction() == 1) {
            AlertDialog.Builder builder = new AlertDialog.Builder(getParentActivity());
            builder.setTitle(LocaleController.getString("PassportSelectGender", R.string.PassportSelectGender));
            builder.setItems(new CharSequence[]{LocaleController.getString("PassportMale", R.string.PassportMale), LocaleController.getString("PassportFemale", R.string.PassportFemale)}, new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PassportActivity$ISg888XPXlFztorRao6L_SZAHH8
                @Override // android.content.DialogInterface.OnClickListener
                public final void onClick(DialogInterface dialogInterface, int i) {
                    this.f$0.lambda$null$51$PassportActivity(dialogInterface, i);
                }
            });
            builder.setPositiveButton(LocaleController.getString("Cancel", R.string.Cancel), null);
            showDialog(builder.create());
        }
        return true;
    }

    public /* synthetic */ void lambda$null$51$PassportActivity(DialogInterface dialogInterface, int i) {
        if (i == 0) {
            this.currentGender = "male";
            this.inputFields[4].setText(LocaleController.getString("PassportMale", R.string.PassportMale));
        } else if (i == 1) {
            this.currentGender = "female";
            this.inputFields[4].setText(LocaleController.getString("PassportFemale", R.string.PassportFemale));
        }
    }

    public /* synthetic */ boolean lambda$createIdentityInterface$53$PassportActivity(TextView textView, int i, KeyEvent keyEvent) {
        if (i == 5) {
            int num = ((Integer) textView.getTag()).intValue() + 1;
            EditTextBoldCursor[] editTextBoldCursorArr = this.inputFields;
            if (num < editTextBoldCursorArr.length) {
                if (editTextBoldCursorArr[num].isFocusable()) {
                    this.inputFields[num].requestFocus();
                } else {
                    this.inputFields[num].dispatchTouchEvent(MotionEvent.obtain(0L, 0L, 1, 0.0f, 0.0f, 0));
                    textView.clearFocus();
                    AndroidUtilities.hideKeyboard(textView);
                }
            }
            return true;
        }
        return false;
    }

    public /* synthetic */ boolean lambda$createIdentityInterface$54$PassportActivity(TextView textView, int i, KeyEvent keyEvent) {
        if (i == 5) {
            int num = ((Integer) textView.getTag()).intValue() + 1;
            EditTextBoldCursor[] editTextBoldCursorArr = this.inputExtraFields;
            if (num < editTextBoldCursorArr.length) {
                if (editTextBoldCursorArr[num].isFocusable()) {
                    this.inputExtraFields[num].requestFocus();
                } else {
                    this.inputExtraFields[num].dispatchTouchEvent(MotionEvent.obtain(0L, 0L, 1, 0.0f, 0.0f, 0));
                    textView.clearFocus();
                    AndroidUtilities.hideKeyboard(textView);
                }
            }
            return true;
        }
        return false;
    }

    public /* synthetic */ void lambda$createIdentityInterface$55$PassportActivity(View v) {
        createDocumentDeleteAlert();
    }

    private void updateInterfaceStringsForDocumentType() {
        if (this.currentDocumentsType != null) {
            this.actionBar.setTitle(getTextForType(this.currentDocumentsType.type));
        } else {
            this.actionBar.setTitle(LocaleController.getString("PassportPersonal", R.string.PassportPersonal));
        }
        updateUploadText(2);
        updateUploadText(3);
        updateUploadText(1);
        updateUploadText(4);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void updateUploadText(int type) {
        boolean z = true;
        if (type == 0) {
            if (this.uploadDocumentCell == null) {
                return;
            }
            if (this.documents.size() >= 1) {
                this.uploadDocumentCell.setText(LocaleController.getString("PassportUploadAdditinalDocument", R.string.PassportUploadAdditinalDocument), false);
                return;
            } else {
                this.uploadDocumentCell.setText(LocaleController.getString("PassportUploadDocument", R.string.PassportUploadDocument), false);
                return;
            }
        }
        if (type == 1) {
            TextDetailSettingsCell textDetailSettingsCell = this.uploadSelfieCell;
            if (textDetailSettingsCell == null) {
                return;
            }
            textDetailSettingsCell.setVisibility(this.selfieDocument != null ? 8 : 0);
            return;
        }
        if (type == 4) {
            if (this.uploadTranslationCell == null) {
                return;
            }
            if (this.translationDocuments.size() >= 1) {
                this.uploadTranslationCell.setText(LocaleController.getString("PassportUploadAdditinalDocument", R.string.PassportUploadAdditinalDocument), false);
                return;
            } else {
                this.uploadTranslationCell.setText(LocaleController.getString("PassportUploadDocument", R.string.PassportUploadDocument), false);
                return;
            }
        }
        if (type == 2) {
            if (this.uploadFrontCell == null) {
                return;
            }
            TLRPC.TL_secureRequiredType tL_secureRequiredType = this.currentDocumentsType;
            if (tL_secureRequiredType == null || (!tL_secureRequiredType.selfie_required && !(this.currentDocumentsType.type instanceof TLRPC.TL_secureValueTypeIdentityCard) && !(this.currentDocumentsType.type instanceof TLRPC.TL_secureValueTypeDriverLicense))) {
                z = false;
            }
            boolean divider = z;
            if ((this.currentDocumentsType.type instanceof TLRPC.TL_secureValueTypePassport) || (this.currentDocumentsType.type instanceof TLRPC.TL_secureValueTypeInternalPassport)) {
                this.uploadFrontCell.setTextAndValue(LocaleController.getString("PassportMainPage", R.string.PassportMainPage), LocaleController.getString("PassportMainPageInfo", R.string.PassportMainPageInfo), divider);
            } else {
                this.uploadFrontCell.setTextAndValue(LocaleController.getString("PassportFrontSide", R.string.PassportFrontSide), LocaleController.getString("PassportFrontSideInfo", R.string.PassportFrontSideInfo), divider);
            }
            this.uploadFrontCell.setVisibility(this.frontDocument != null ? 8 : 0);
            return;
        }
        if (type != 3 || this.uploadReverseCell == null) {
            return;
        }
        if (!(this.currentDocumentsType.type instanceof TLRPC.TL_secureValueTypeIdentityCard) && !(this.currentDocumentsType.type instanceof TLRPC.TL_secureValueTypeDriverLicense)) {
            this.reverseLayout.setVisibility(8);
            this.uploadReverseCell.setVisibility(8);
        } else {
            this.reverseLayout.setVisibility(0);
            this.uploadReverseCell.setVisibility(this.reverseDocument != null ? 8 : 0);
        }
    }

    private void checkTopErrorCell(boolean init) {
        String errorText;
        String errorText2;
        if (this.topErrorCell == null) {
            return;
        }
        SpannableStringBuilder stringBuilder = null;
        if (this.fieldsErrors != null && ((init || this.errorsValues.containsKey("error_all")) && (errorText2 = this.fieldsErrors.get("error_all")) != null)) {
            stringBuilder = new SpannableStringBuilder(errorText2);
            if (init) {
                this.errorsValues.put("error_all", "");
            }
        }
        if (this.documentsErrors != null && ((init || this.errorsValues.containsKey("error_document_all")) && (errorText = this.documentsErrors.get("error_all")) != null)) {
            if (stringBuilder == null) {
                stringBuilder = new SpannableStringBuilder(errorText);
            } else {
                stringBuilder.append((CharSequence) "\n\n").append((CharSequence) errorText);
            }
            if (init) {
                this.errorsValues.put("error_document_all", "");
            }
        }
        if (stringBuilder != null) {
            stringBuilder.setSpan(new ForegroundColorSpan(Theme.getColor(Theme.key_windowBackgroundWhiteRedText3)), 0, stringBuilder.length(), 33);
            this.topErrorCell.setText(stringBuilder);
            this.topErrorCell.setVisibility(0);
        } else if (this.topErrorCell.getVisibility() != 8) {
            this.topErrorCell.setVisibility(8);
        }
    }

    private void addDocumentViewInternal(TLRPC.TL_secureFile f, int uploadingType) {
        SecureDocumentKey secureDocumentKey = getSecureDocumentKey(f.secret, f.file_hash);
        SecureDocument secureDocument = new SecureDocument(secureDocumentKey, f, null, null, null);
        addDocumentView(secureDocument, uploadingType);
    }

    private void addDocumentViews(ArrayList<TLRPC.SecureFile> files) {
        this.documents.clear();
        int size = files.size();
        for (int a = 0; a < size; a++) {
            TLRPC.SecureFile secureFile = files.get(a);
            if (secureFile instanceof TLRPC.TL_secureFile) {
                addDocumentViewInternal((TLRPC.TL_secureFile) secureFile, 0);
            }
        }
    }

    private void addTranslationDocumentViews(ArrayList<TLRPC.SecureFile> files) {
        this.translationDocuments.clear();
        int size = files.size();
        for (int a = 0; a < size; a++) {
            TLRPC.SecureFile secureFile = files.get(a);
            if (secureFile instanceof TLRPC.TL_secureFile) {
                addDocumentViewInternal((TLRPC.TL_secureFile) secureFile, 4);
            }
        }
    }

    /* JADX WARN: Failed to restore switch over string. Please report as a decompilation issue */
    private void setFieldValues(HashMap<String, String> values, EditTextBoldCursor editText, String key) {
        String value;
        String value2;
        String value3 = values.get(key);
        if (value3 != null) {
            byte b = -1;
            switch (key.hashCode()) {
                case -2006252145:
                    if (key.equals("residence_country_code")) {
                        b = 1;
                    }
                    break;
                case -1249512767:
                    if (key.equals("gender")) {
                        b = 2;
                    }
                    break;
                case 475919162:
                    if (key.equals("expiry_date")) {
                        b = 3;
                    }
                    break;
                case 1481071862:
                    if (key.equals("country_code")) {
                        b = 0;
                    }
                    break;
            }
            if (b == 0) {
                this.currentCitizeship = value3;
                String country = this.languageMap.get(value3);
                if (country != null) {
                    editText.setText(country);
                }
            } else if (b == 1) {
                this.currentResidence = value3;
                String country2 = this.languageMap.get(value3);
                if (country2 != null) {
                    editText.setText(country2);
                }
            } else if (b != 2) {
                if (b == 3) {
                    boolean ok = false;
                    if (!TextUtils.isEmpty(value3)) {
                        String[] args = value3.split("\\.");
                        if (args.length == 3) {
                            this.currentExpireDate[0] = Utilities.parseInt(args[2]).intValue();
                            this.currentExpireDate[1] = Utilities.parseInt(args[1]).intValue();
                            this.currentExpireDate[2] = Utilities.parseInt(args[0]).intValue();
                            editText.setText(value3);
                            ok = true;
                        }
                    }
                    if (!ok) {
                        int[] iArr = this.currentExpireDate;
                        iArr[2] = 0;
                        iArr[1] = 0;
                        iArr[0] = 0;
                        editText.setText(LocaleController.getString("PassportNoExpireDate", R.string.PassportNoExpireDate));
                    }
                } else {
                    editText.setText(value3);
                }
            } else if ("male".equals(value3)) {
                this.currentGender = value3;
                editText.setText(LocaleController.getString("PassportMale", R.string.PassportMale));
            } else if ("female".equals(value3)) {
                this.currentGender = value3;
                editText.setText(LocaleController.getString("PassportFemale", R.string.PassportFemale));
            }
        }
        HashMap<String, String> map = this.fieldsErrors;
        if (map != null && (value2 = map.get(key)) != null) {
            editText.setErrorText(value2);
            this.errorsValues.put(key, editText.getText().toString());
            return;
        }
        HashMap<String, String> map2 = this.documentsErrors;
        if (map2 != null && (value = map2.get(key)) != null) {
            editText.setErrorText(value);
            this.errorsValues.put(key, editText.getText().toString());
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:50:0x0152  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    private void addDocumentView(final im.uwrkaxlmjj.messenger.SecureDocument r13, final int r14) {
        /*
            Method dump skipped, instruction units count: 373
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.ui.PassportActivity.addDocumentView(im.uwrkaxlmjj.messenger.SecureDocument, int):void");
    }

    public /* synthetic */ void lambda$addDocumentView$56$PassportActivity(int type, View v) {
        this.uploadingFileType = type;
        if (type == 1) {
            this.currentPhotoViewerLayout = this.selfieLayout;
        } else if (type == 4) {
            this.currentPhotoViewerLayout = this.translationLayout;
        } else if (type == 2) {
            this.currentPhotoViewerLayout = this.frontLayout;
        } else if (type == 3) {
            this.currentPhotoViewerLayout = this.reverseLayout;
        } else {
            this.currentPhotoViewerLayout = this.documentsLayout;
        }
        SecureDocument document1 = (SecureDocument) v.getTag();
        PhotoViewer.getInstance().setParentActivity(getParentActivity());
        if (type == 0) {
            PhotoViewer photoViewer = PhotoViewer.getInstance();
            ArrayList<SecureDocument> arrayList = this.documents;
            photoViewer.openPhoto(arrayList, arrayList.indexOf(document1), this.provider);
        } else {
            PhotoViewer photoViewer2 = PhotoViewer.getInstance();
            ArrayList<SecureDocument> arrayList2 = this.translationDocuments;
            photoViewer2.openPhoto(arrayList2, arrayList2.indexOf(document1), this.provider);
        }
    }

    public /* synthetic */ boolean lambda$addDocumentView$58$PassportActivity(final int type, final SecureDocument document, final SecureDocumentCell cell, final String key, View v) {
        AlertDialog.Builder builder = new AlertDialog.Builder(getParentActivity());
        if (type == 1) {
            builder.setMessage(LocaleController.getString("PassportDeleteSelfie", R.string.PassportDeleteSelfie));
        } else {
            builder.setMessage(LocaleController.getString("PassportDeleteScan", R.string.PassportDeleteScan));
        }
        builder.setNegativeButton(LocaleController.getString("Cancel", R.string.Cancel), null);
        builder.setTitle(LocaleController.getString("AppName", R.string.AppName));
        builder.setPositiveButton(LocaleController.getString("OK", R.string.OK), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PassportActivity$q8zGx9IQqgc4bJrZtgG91RfTROU
            @Override // android.content.DialogInterface.OnClickListener
            public final void onClick(DialogInterface dialogInterface, int i) {
                this.f$0.lambda$null$57$PassportActivity(document, type, cell, key, dialogInterface, i);
            }
        });
        showDialog(builder.create());
        return true;
    }

    public /* synthetic */ void lambda$null$57$PassportActivity(SecureDocument document, int type, SecureDocumentCell cell, String key, DialogInterface dialog, int which) {
        this.documentsCells.remove(document);
        if (type == 1) {
            this.selfieDocument = null;
            this.selfieLayout.removeView(cell);
        } else if (type == 4) {
            this.translationDocuments.remove(document);
            this.translationLayout.removeView(cell);
        } else if (type == 2) {
            this.frontDocument = null;
            this.frontLayout.removeView(cell);
        } else if (type == 3) {
            this.reverseDocument = null;
            this.reverseLayout.removeView(cell);
        } else {
            this.documents.remove(document);
            this.documentsLayout.removeView(cell);
        }
        if (key != null) {
            HashMap<String, String> map = this.documentsErrors;
            if (map != null) {
                map.remove(key);
            }
            HashMap<String, String> map2 = this.errorsValues;
            if (map2 != null) {
                map2.remove(key);
            }
        }
        updateUploadText(type);
        if (document.path != null && this.uploadingDocuments.remove(document.path) != null) {
            if (this.uploadingDocuments.isEmpty()) {
                this.doneItem.setEnabled(true);
                this.doneItem.setAlpha(1.0f);
            }
            FileLoader.getInstance(this.currentAccount).cancelUploadFile(document.path, false);
        }
    }

    private String getNameForType(TLRPC.SecureValueType type) {
        if (type instanceof TLRPC.TL_secureValueTypePersonalDetails) {
            return "personal_details";
        }
        if (type instanceof TLRPC.TL_secureValueTypePassport) {
            return "passport";
        }
        if (type instanceof TLRPC.TL_secureValueTypeInternalPassport) {
            return "internal_passport";
        }
        if (type instanceof TLRPC.TL_secureValueTypeDriverLicense) {
            return "driver_license";
        }
        if (type instanceof TLRPC.TL_secureValueTypeIdentityCard) {
            return "identity_card";
        }
        if (type instanceof TLRPC.TL_secureValueTypeUtilityBill) {
            return "utility_bill";
        }
        if (type instanceof TLRPC.TL_secureValueTypeAddress) {
            return "address";
        }
        if (type instanceof TLRPC.TL_secureValueTypeBankStatement) {
            return "bank_statement";
        }
        if (type instanceof TLRPC.TL_secureValueTypeRentalAgreement) {
            return "rental_agreement";
        }
        if (type instanceof TLRPC.TL_secureValueTypeTemporaryRegistration) {
            return "temporary_registration";
        }
        if (type instanceof TLRPC.TL_secureValueTypePassportRegistration) {
            return "passport_registration";
        }
        if (type instanceof TLRPC.TL_secureValueTypeEmail) {
            return "email";
        }
        if (type instanceof TLRPC.TL_secureValueTypePhone) {
            return "phone";
        }
        return "";
    }

    private TextDetailSecureCell getViewByType(TLRPC.TL_secureRequiredType requiredType) {
        TLRPC.TL_secureRequiredType requiredType2;
        TextDetailSecureCell view = this.typesViews.get(requiredType);
        if (view == null && (requiredType2 = this.documentsToTypesLink.get(requiredType)) != null) {
            return this.typesViews.get(requiredType2);
        }
        return view;
    }

    private String getTextForType(TLRPC.SecureValueType type) {
        if (type instanceof TLRPC.TL_secureValueTypePassport) {
            return LocaleController.getString("ActionBotDocumentPassport", R.string.ActionBotDocumentPassport);
        }
        if (type instanceof TLRPC.TL_secureValueTypeDriverLicense) {
            return LocaleController.getString("ActionBotDocumentDriverLicence", R.string.ActionBotDocumentDriverLicence);
        }
        if (type instanceof TLRPC.TL_secureValueTypeIdentityCard) {
            return LocaleController.getString("ActionBotDocumentIdentityCard", R.string.ActionBotDocumentIdentityCard);
        }
        if (type instanceof TLRPC.TL_secureValueTypeUtilityBill) {
            return LocaleController.getString("ActionBotDocumentUtilityBill", R.string.ActionBotDocumentUtilityBill);
        }
        if (type instanceof TLRPC.TL_secureValueTypeBankStatement) {
            return LocaleController.getString("ActionBotDocumentBankStatement", R.string.ActionBotDocumentBankStatement);
        }
        if (type instanceof TLRPC.TL_secureValueTypeRentalAgreement) {
            return LocaleController.getString("ActionBotDocumentRentalAgreement", R.string.ActionBotDocumentRentalAgreement);
        }
        if (type instanceof TLRPC.TL_secureValueTypeInternalPassport) {
            return LocaleController.getString("ActionBotDocumentInternalPassport", R.string.ActionBotDocumentInternalPassport);
        }
        if (type instanceof TLRPC.TL_secureValueTypePassportRegistration) {
            return LocaleController.getString("ActionBotDocumentPassportRegistration", R.string.ActionBotDocumentPassportRegistration);
        }
        if (type instanceof TLRPC.TL_secureValueTypeTemporaryRegistration) {
            return LocaleController.getString("ActionBotDocumentTemporaryRegistration", R.string.ActionBotDocumentTemporaryRegistration);
        }
        if (type instanceof TLRPC.TL_secureValueTypePhone) {
            return LocaleController.getString("ActionBotDocumentPhone", R.string.ActionBotDocumentPhone);
        }
        if (type instanceof TLRPC.TL_secureValueTypeEmail) {
            return LocaleController.getString("ActionBotDocumentEmail", R.string.ActionBotDocumentEmail);
        }
        return "";
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* JADX WARN: Removed duplicated region for block: B:115:0x0238  */
    /* JADX WARN: Removed duplicated region for block: B:173:0x0328  */
    /* JADX WARN: Removed duplicated region for block: B:185:0x034a  */
    /* JADX WARN: Removed duplicated region for block: B:196:0x037e A[Catch: Exception -> 0x0399, TryCatch #4 {Exception -> 0x0399, blocks: (B:147:0x02b8, B:149:0x02c4, B:151:0x02cc, B:154:0x02db, B:156:0x02e1, B:158:0x02eb, B:160:0x02f3, B:162:0x02fd, B:165:0x0306, B:166:0x030c, B:167:0x0311, B:189:0x0350, B:190:0x0354, B:192:0x035c, B:193:0x0369, B:195:0x0371, B:196:0x037e, B:198:0x0389, B:174:0x0329, B:177:0x0333, B:180:0x033d), top: B:332:0x02b8 }] */
    /* JADX WARN: Removed duplicated region for block: B:198:0x0389 A[Catch: Exception -> 0x0399, TRY_LEAVE, TryCatch #4 {Exception -> 0x0399, blocks: (B:147:0x02b8, B:149:0x02c4, B:151:0x02cc, B:154:0x02db, B:156:0x02e1, B:158:0x02eb, B:160:0x02f3, B:162:0x02fd, B:165:0x0306, B:166:0x030c, B:167:0x0311, B:189:0x0350, B:190:0x0354, B:192:0x035c, B:193:0x0369, B:195:0x0371, B:196:0x037e, B:198:0x0389, B:174:0x0329, B:177:0x0333, B:180:0x033d), top: B:332:0x02b8 }] */
    /* JADX WARN: Removed duplicated region for block: B:219:0x0417  */
    /* JADX WARN: Removed duplicated region for block: B:220:0x041c A[PHI: r24
      0x041c: PHI (r24v9 'value' java.lang.String) = (r24v6 'value' java.lang.String), (r24v10 'value' java.lang.String) binds: [B:218:0x0415, B:51:0x0128] A[DONT_GENERATE, DONT_INLINE]] */
    /* JADX WARN: Removed duplicated region for block: B:88:0x01b8  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public void setTypeValue(im.uwrkaxlmjj.tgnet.TLRPC.TL_secureRequiredType r37, java.lang.String r38, java.lang.String r39, im.uwrkaxlmjj.tgnet.TLRPC.TL_secureRequiredType r40, java.lang.String r41, boolean r42, int r43) {
        /*
            Method dump skipped, instruction units count: 1520
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.ui.PassportActivity.setTypeValue(im.uwrkaxlmjj.tgnet.TLRPC$TL_secureRequiredType, java.lang.String, java.lang.String, im.uwrkaxlmjj.tgnet.TLRPC$TL_secureRequiredType, java.lang.String, boolean, int):void");
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void checkNativeFields(boolean byEdit) {
        EditTextBoldCursor[] editTextBoldCursorArr;
        if (this.inputExtraFields == null) {
            return;
        }
        String country = this.languageMap.get(this.currentResidence);
        HashMap<String, String> map = SharedConfig.getCountryLangs();
        String lang = map.get(this.currentResidence);
        if (!this.currentType.native_names || TextUtils.isEmpty(this.currentResidence) || "EN".equals(lang)) {
            if (this.nativeInfoCell.getVisibility() != 8) {
                this.nativeInfoCell.setVisibility(8);
                this.headerCell.setVisibility(8);
                this.extraBackgroundView2.setVisibility(8);
                int a = 0;
                while (true) {
                    EditTextBoldCursor[] editTextBoldCursorArr2 = this.inputExtraFields;
                    if (a >= editTextBoldCursorArr2.length) {
                        break;
                    }
                    ((View) editTextBoldCursorArr2[a].getParent()).setVisibility(8);
                    a++;
                }
                int a2 = this.currentBotId;
                if (((a2 != 0 || this.currentDocumentsType == null) && this.currentTypeValue != null && !this.documentOnly) || this.currentDocumentsTypeValue != null) {
                    this.sectionCell2.setBackgroundDrawable(Theme.getThemedDrawable(getParentActivity(), R.drawable.greydivider, Theme.key_windowBackgroundGrayShadow));
                    return;
                } else {
                    this.sectionCell2.setBackgroundDrawable(Theme.getThemedDrawable(getParentActivity(), R.drawable.greydivider_bottom, Theme.key_windowBackgroundGrayShadow));
                    return;
                }
            }
            return;
        }
        if (this.nativeInfoCell.getVisibility() != 0) {
            this.nativeInfoCell.setVisibility(0);
            this.headerCell.setVisibility(0);
            this.extraBackgroundView2.setVisibility(0);
            int a3 = 0;
            while (true) {
                editTextBoldCursorArr = this.inputExtraFields;
                if (a3 >= editTextBoldCursorArr.length) {
                    break;
                }
                ((View) editTextBoldCursorArr[a3].getParent()).setVisibility(0);
                a3++;
            }
            if (editTextBoldCursorArr[0].length() == 0 && this.inputExtraFields[1].length() == 0 && this.inputExtraFields[2].length() == 0) {
                int a4 = 0;
                while (true) {
                    boolean[] zArr = this.nonLatinNames;
                    if (a4 >= zArr.length) {
                        break;
                    }
                    if (!zArr[a4]) {
                        a4++;
                    } else {
                        this.inputExtraFields[0].setText(this.inputFields[0].getText());
                        this.inputExtraFields[1].setText(this.inputFields[1].getText());
                        this.inputExtraFields[2].setText(this.inputFields[2].getText());
                        break;
                    }
                }
            }
            this.sectionCell2.setBackgroundDrawable(Theme.getThemedDrawable(getParentActivity(), R.drawable.greydivider, Theme.key_windowBackgroundGrayShadow));
        }
        this.nativeInfoCell.setText(LocaleController.formatString("PassportNativeInfo", R.string.PassportNativeInfo, country));
        String header = lang != null ? LocaleController.getServerString("PassportLanguage_" + lang) : null;
        if (header != null) {
            this.headerCell.setText(LocaleController.formatString("PassportNativeHeaderLang", R.string.PassportNativeHeaderLang, header));
        } else {
            this.headerCell.setText(LocaleController.getString("PassportNativeHeader", R.string.PassportNativeHeader));
        }
        for (int a5 = 0; a5 < 3; a5++) {
            if (a5 != 0) {
                if (a5 != 1) {
                    if (a5 == 2) {
                        if (header != null) {
                            this.inputExtraFields[a5].setHintText(LocaleController.getString("PassportSurname", R.string.PassportSurname));
                        } else {
                            this.inputExtraFields[a5].setHintText(LocaleController.formatString("PassportSurnameCountry", R.string.PassportSurnameCountry, country));
                        }
                    }
                } else if (header != null) {
                    this.inputExtraFields[a5].setHintText(LocaleController.getString("PassportMidname", R.string.PassportMidname));
                } else {
                    this.inputExtraFields[a5].setHintText(LocaleController.formatString("PassportMidnameCountry", R.string.PassportMidnameCountry, country));
                }
            } else if (header != null) {
                this.inputExtraFields[a5].setHintText(LocaleController.getString("PassportName", R.string.PassportName));
            } else {
                this.inputExtraFields[a5].setHintText(LocaleController.formatString("PassportNameCountry", R.string.PassportNameCountry, country));
            }
        }
        if (byEdit) {
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PassportActivity$AUsTNXjOUCKTdy4xsK9W-g9KWho
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$checkNativeFields$59$PassportActivity();
                }
            });
        }
    }

    public /* synthetic */ void lambda$checkNativeFields$59$PassportActivity() {
        EditTextBoldCursor[] editTextBoldCursorArr = this.inputExtraFields;
        if (editTextBoldCursorArr != null) {
            scrollToField(editTextBoldCursorArr[0]);
        }
    }

    private String getErrorsString(HashMap<String, String> errors, HashMap<String, String> documentErrors) {
        HashMap<String, String> hashMap;
        StringBuilder stringBuilder = new StringBuilder();
        for (int a = 0; a < 2; a++) {
            if (a == 0) {
                hashMap = errors;
            } else {
                hashMap = documentErrors;
            }
            if (hashMap != null) {
                for (Map.Entry<String, String> entry : hashMap.entrySet()) {
                    String value = entry.getValue();
                    if (stringBuilder.length() > 0) {
                        stringBuilder.append(", ");
                        value = value.toLowerCase();
                    }
                    if (value.endsWith(".")) {
                        value = value.substring(0, value.length() - 1);
                    }
                    stringBuilder.append(value);
                }
            }
        }
        int a2 = stringBuilder.length();
        if (a2 > 0) {
            stringBuilder.append('.');
        }
        return stringBuilder.toString();
    }

    private TLRPC.TL_secureValue getValueByType(TLRPC.TL_secureRequiredType requiredType, boolean check) {
        String[] keys;
        if (requiredType == null) {
            return null;
        }
        int size = this.currentForm.values.size();
        for (int a = 0; a < size; a++) {
            TLRPC.TL_secureValue secureValue = this.currentForm.values.get(a);
            if (requiredType.type.getClass() == secureValue.type.getClass()) {
                if (check) {
                    if (requiredType.selfie_required && !(secureValue.selfie instanceof TLRPC.TL_secureFile)) {
                        return null;
                    }
                    if (requiredType.translation_required && secureValue.translation.isEmpty()) {
                        return null;
                    }
                    if (isAddressDocument(requiredType.type) && secureValue.files.isEmpty()) {
                        return null;
                    }
                    if (isPersonalDocument(requiredType.type) && !(secureValue.front_side instanceof TLRPC.TL_secureFile)) {
                        return null;
                    }
                    if (((requiredType.type instanceof TLRPC.TL_secureValueTypeDriverLicense) || (requiredType.type instanceof TLRPC.TL_secureValueTypeIdentityCard)) && !(secureValue.reverse_side instanceof TLRPC.TL_secureFile)) {
                        return null;
                    }
                    if ((requiredType.type instanceof TLRPC.TL_secureValueTypePersonalDetails) || (requiredType.type instanceof TLRPC.TL_secureValueTypeAddress)) {
                        if (requiredType.type instanceof TLRPC.TL_secureValueTypePersonalDetails) {
                            if (requiredType.native_names) {
                                keys = new String[]{"first_name_native", "last_name_native", "birth_date", "gender", "country_code", "residence_country_code"};
                            } else {
                                keys = new String[]{"first_name", "last_name", "birth_date", "gender", "country_code", "residence_country_code"};
                            }
                        } else {
                            keys = new String[]{"street_line1", "street_line2", "post_code", "city", RemoteConfigConstants.ResponseFieldKey.STATE, "country_code"};
                        }
                        try {
                            JSONObject jsonObject = new JSONObject(decryptData(secureValue.data.data, decryptValueSecret(secureValue.data.secret, secureValue.data.data_hash), secureValue.data.data_hash));
                            for (int b = 0; b < keys.length; b++) {
                                if (!jsonObject.has(keys[b]) || TextUtils.isEmpty(jsonObject.getString(keys[b]))) {
                                    return null;
                                }
                            }
                        } catch (Throwable th) {
                            return null;
                        }
                    }
                }
                return secureValue;
            }
        }
        return null;
    }

    private void openTypeActivity(TLRPC.TL_secureRequiredType requiredType, TLRPC.TL_secureRequiredType documentRequiredType, ArrayList<TLRPC.TL_secureRequiredType> availableDocumentTypes, final boolean documentOnly) {
        int activityType;
        HashMap<String, String> map;
        HashMap<String, String> map2;
        final int availableDocumentTypesCount = availableDocumentTypes != null ? availableDocumentTypes.size() : 0;
        final TLRPC.SecureValueType type = requiredType.type;
        TLRPC.SecureValueType documentType = documentRequiredType != null ? documentRequiredType.type : null;
        if (type instanceof TLRPC.TL_secureValueTypePersonalDetails) {
            activityType = 1;
        } else if (type instanceof TLRPC.TL_secureValueTypeAddress) {
            activityType = 2;
        } else if (type instanceof TLRPC.TL_secureValueTypePhone) {
            activityType = 3;
        } else if (!(type instanceof TLRPC.TL_secureValueTypeEmail)) {
            activityType = -1;
        } else {
            activityType = 4;
        }
        if (activityType != -1) {
            if (!documentOnly) {
                map = this.errorsMap.get(getNameForType(type));
            } else {
                map = null;
            }
            HashMap<String, String> errors = map;
            HashMap<String, String> documentsErrors = this.errorsMap.get(getNameForType(documentType));
            TLRPC.TL_secureValue value = getValueByType(requiredType, false);
            TLRPC.TL_secureValue documentsValue = getValueByType(documentRequiredType, false);
            TLRPC.TL_account_authorizationForm tL_account_authorizationForm = this.currentForm;
            TLRPC.TL_account_password tL_account_password = this.currentPassword;
            HashMap<String, String> map3 = this.typesValues.get(requiredType);
            if (documentRequiredType != null) {
                map2 = this.typesValues.get(documentRequiredType);
            } else {
                map2 = null;
            }
            int activityType2 = activityType;
            PassportActivity activity = new PassportActivity(activityType, tL_account_authorizationForm, tL_account_password, requiredType, value, documentRequiredType, documentsValue, map3, map2);
            activity.delegate = new PassportActivityDelegate() { // from class: im.uwrkaxlmjj.ui.PassportActivity.19
                private TLRPC.InputSecureFile getInputSecureFile(SecureDocument document) {
                    if (document.inputFile != null) {
                        TLRPC.TL_inputSecureFileUploaded inputSecureFileUploaded = new TLRPC.TL_inputSecureFileUploaded();
                        inputSecureFileUploaded.id = document.inputFile.id;
                        inputSecureFileUploaded.parts = document.inputFile.parts;
                        inputSecureFileUploaded.md5_checksum = document.inputFile.md5_checksum;
                        inputSecureFileUploaded.file_hash = document.fileHash;
                        inputSecureFileUploaded.secret = document.fileSecret;
                        return inputSecureFileUploaded;
                    }
                    TLRPC.TL_inputSecureFile inputSecureFile = new TLRPC.TL_inputSecureFile();
                    inputSecureFile.id = document.secureFile.id;
                    inputSecureFile.access_hash = document.secureFile.access_hash;
                    return inputSecureFile;
                }

                /* JADX INFO: Access modifiers changed from: private */
                public void renameFile(SecureDocument oldDocument, TLRPC.TL_secureFile newSecureFile) {
                    File oldFile = FileLoader.getPathToAttach(oldDocument);
                    String oldKey = oldDocument.secureFile.dc_id + "_" + oldDocument.secureFile.id;
                    File newFile = FileLoader.getPathToAttach(newSecureFile);
                    String newKey = newSecureFile.dc_id + "_" + newSecureFile.id;
                    oldFile.renameTo(newFile);
                    ImageLoader.getInstance().replaceImageInCache(oldKey, newKey, null, false);
                }

                @Override // im.uwrkaxlmjj.ui.PassportActivity.PassportActivityDelegate
                public void saveValue(TLRPC.TL_secureRequiredType tL_secureRequiredType, String str, String str2, TLRPC.TL_secureRequiredType tL_secureRequiredType2, String str3, ArrayList<SecureDocument> arrayList, SecureDocument secureDocument, ArrayList<SecureDocument> arrayList2, SecureDocument secureDocument2, SecureDocument secureDocument3, Runnable runnable, ErrorRunnable errorRunnable) {
                    TLRPC.SecurePlainData securePlainData;
                    TLRPC.TL_inputSecureValue tL_inputSecureValue;
                    TLRPC.TL_inputSecureValue tL_inputSecureValue2;
                    TLRPC.TL_inputSecureValue tL_inputSecureValue3 = null;
                    if (!TextUtils.isEmpty(str2)) {
                        tL_inputSecureValue3 = new TLRPC.TL_inputSecureValue();
                        tL_inputSecureValue3.type = tL_secureRequiredType.type;
                        tL_inputSecureValue3.flags |= 1;
                        EncryptionResult encryptionResultEncryptData = PassportActivity.this.encryptData(AndroidUtilities.getStringBytes(str2));
                        tL_inputSecureValue3.data = new TLRPC.TL_secureData();
                        tL_inputSecureValue3.data.data = encryptionResultEncryptData.encryptedData;
                        tL_inputSecureValue3.data.data_hash = encryptionResultEncryptData.fileHash;
                        tL_inputSecureValue3.data.secret = encryptionResultEncryptData.fileSecret;
                    } else if (!TextUtils.isEmpty(str)) {
                        TLRPC.SecureValueType secureValueType = type;
                        if (secureValueType instanceof TLRPC.TL_secureValueTypeEmail) {
                            TLRPC.TL_securePlainEmail tL_securePlainEmail = new TLRPC.TL_securePlainEmail();
                            tL_securePlainEmail.email = str;
                            securePlainData = tL_securePlainEmail;
                        } else if (secureValueType instanceof TLRPC.TL_secureValueTypePhone) {
                            TLRPC.TL_securePlainPhone tL_securePlainPhone = new TLRPC.TL_securePlainPhone();
                            tL_securePlainPhone.phone = str;
                            securePlainData = tL_securePlainPhone;
                        } else {
                            return;
                        }
                        tL_inputSecureValue3 = new TLRPC.TL_inputSecureValue();
                        tL_inputSecureValue3.type = tL_secureRequiredType.type;
                        tL_inputSecureValue3.flags |= 32;
                        tL_inputSecureValue3.plain_data = securePlainData;
                    }
                    if (!documentOnly && tL_inputSecureValue3 == null) {
                        if (errorRunnable != null) {
                            errorRunnable.onError(null, null);
                            return;
                        }
                        return;
                    }
                    if (tL_secureRequiredType2 != null) {
                        TLRPC.TL_inputSecureValue tL_inputSecureValue4 = new TLRPC.TL_inputSecureValue();
                        tL_inputSecureValue4.type = tL_secureRequiredType2.type;
                        if (!TextUtils.isEmpty(str3)) {
                            tL_inputSecureValue4.flags |= 1;
                            EncryptionResult encryptionResultEncryptData2 = PassportActivity.this.encryptData(AndroidUtilities.getStringBytes(str3));
                            tL_inputSecureValue4.data = new TLRPC.TL_secureData();
                            tL_inputSecureValue4.data.data = encryptionResultEncryptData2.encryptedData;
                            tL_inputSecureValue4.data.data_hash = encryptionResultEncryptData2.fileHash;
                            tL_inputSecureValue4.data.secret = encryptionResultEncryptData2.fileSecret;
                        }
                        if (secureDocument2 != null) {
                            tL_inputSecureValue4.front_side = getInputSecureFile(secureDocument2);
                            tL_inputSecureValue4.flags |= 2;
                        }
                        if (secureDocument3 != null) {
                            tL_inputSecureValue4.reverse_side = getInputSecureFile(secureDocument3);
                            tL_inputSecureValue4.flags |= 4;
                        }
                        if (secureDocument != null) {
                            tL_inputSecureValue4.selfie = getInputSecureFile(secureDocument);
                            tL_inputSecureValue4.flags |= 8;
                        }
                        if (arrayList2 != null && !arrayList2.isEmpty()) {
                            tL_inputSecureValue4.flags |= 64;
                            int size = arrayList2.size();
                            for (int i = 0; i < size; i++) {
                                tL_inputSecureValue4.translation.add(getInputSecureFile(arrayList2.get(i)));
                            }
                        }
                        if (arrayList != null && !arrayList.isEmpty()) {
                            tL_inputSecureValue4.flags |= 16;
                            int size2 = arrayList.size();
                            for (int i2 = 0; i2 < size2; i2++) {
                                tL_inputSecureValue4.files.add(getInputSecureFile(arrayList.get(i2)));
                            }
                        }
                        if (!documentOnly) {
                            tL_inputSecureValue = tL_inputSecureValue3;
                            tL_inputSecureValue2 = tL_inputSecureValue4;
                        } else {
                            tL_inputSecureValue = tL_inputSecureValue4;
                            tL_inputSecureValue2 = null;
                        }
                    } else {
                        tL_inputSecureValue = tL_inputSecureValue3;
                        tL_inputSecureValue2 = null;
                    }
                    TLRPC.TL_account_saveSecureValue tL_account_saveSecureValue = new TLRPC.TL_account_saveSecureValue();
                    tL_account_saveSecureValue.value = tL_inputSecureValue;
                    tL_account_saveSecureValue.secure_secret_id = PassportActivity.this.secureSecretId;
                    ConnectionsManager.getInstance(PassportActivity.this.currentAccount).sendRequest(tL_account_saveSecureValue, new AnonymousClass1(errorRunnable, str, tL_account_saveSecureValue, tL_secureRequiredType2, tL_secureRequiredType, arrayList, secureDocument, secureDocument2, secureDocument3, arrayList2, str2, str3, runnable, this, tL_inputSecureValue2));
                }

                /* JADX INFO: renamed from: im.uwrkaxlmjj.ui.PassportActivity$19$1, reason: invalid class name */
                class AnonymousClass1 implements RequestDelegate {
                    final /* synthetic */ PassportActivityDelegate val$currentDelegate;
                    final /* synthetic */ TLRPC.TL_secureRequiredType val$documentRequiredType;
                    final /* synthetic */ ArrayList val$documents;
                    final /* synthetic */ String val$documentsJson;
                    final /* synthetic */ ErrorRunnable val$errorRunnable;
                    final /* synthetic */ TLRPC.TL_inputSecureValue val$finalFileInputSecureValue;
                    final /* synthetic */ Runnable val$finishRunnable;
                    final /* synthetic */ SecureDocument val$front;
                    final /* synthetic */ String val$json;
                    final /* synthetic */ TLRPC.TL_account_saveSecureValue val$req;
                    final /* synthetic */ TLRPC.TL_secureRequiredType val$requiredType;
                    final /* synthetic */ SecureDocument val$reverse;
                    final /* synthetic */ SecureDocument val$selfie;
                    final /* synthetic */ String val$text;
                    final /* synthetic */ ArrayList val$translationDocuments;

                    AnonymousClass1(ErrorRunnable errorRunnable, String str, TLRPC.TL_account_saveSecureValue tL_account_saveSecureValue, TLRPC.TL_secureRequiredType tL_secureRequiredType, TLRPC.TL_secureRequiredType tL_secureRequiredType2, ArrayList arrayList, SecureDocument secureDocument, SecureDocument secureDocument2, SecureDocument secureDocument3, ArrayList arrayList2, String str2, String str3, Runnable runnable, PassportActivityDelegate passportActivityDelegate, TLRPC.TL_inputSecureValue tL_inputSecureValue) {
                        this.val$errorRunnable = errorRunnable;
                        this.val$text = str;
                        this.val$req = tL_account_saveSecureValue;
                        this.val$documentRequiredType = tL_secureRequiredType;
                        this.val$requiredType = tL_secureRequiredType2;
                        this.val$documents = arrayList;
                        this.val$selfie = secureDocument;
                        this.val$front = secureDocument2;
                        this.val$reverse = secureDocument3;
                        this.val$translationDocuments = arrayList2;
                        this.val$json = str2;
                        this.val$documentsJson = str3;
                        this.val$finishRunnable = runnable;
                        this.val$currentDelegate = passportActivityDelegate;
                        this.val$finalFileInputSecureValue = tL_inputSecureValue;
                    }

                    /* JADX INFO: Access modifiers changed from: private */
                    /* JADX INFO: renamed from: onResult, reason: merged with bridge method [inline-methods] */
                    public void lambda$run$4$PassportActivity$19$1(final TLRPC.TL_error error, final TLRPC.TL_secureValue newValue, final TLRPC.TL_secureValue newPendingValue) {
                        final ErrorRunnable errorRunnable = this.val$errorRunnable;
                        final String str = this.val$text;
                        final TLRPC.TL_account_saveSecureValue tL_account_saveSecureValue = this.val$req;
                        final boolean z = documentOnly;
                        final TLRPC.TL_secureRequiredType tL_secureRequiredType = this.val$documentRequiredType;
                        final TLRPC.TL_secureRequiredType tL_secureRequiredType2 = this.val$requiredType;
                        final ArrayList arrayList = this.val$documents;
                        final SecureDocument secureDocument = this.val$selfie;
                        final SecureDocument secureDocument2 = this.val$front;
                        final SecureDocument secureDocument3 = this.val$reverse;
                        final ArrayList arrayList2 = this.val$translationDocuments;
                        final String str2 = this.val$json;
                        final String str3 = this.val$documentsJson;
                        final int i = availableDocumentTypesCount;
                        final Runnable runnable = this.val$finishRunnable;
                        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PassportActivity$19$1$PVf_O7dEyOWhtheqeSQQeTwoxtA
                            @Override // java.lang.Runnable
                            public final void run() {
                                this.f$0.lambda$onResult$0$PassportActivity$19$1(error, errorRunnable, str, tL_account_saveSecureValue, z, tL_secureRequiredType, tL_secureRequiredType2, newValue, newPendingValue, arrayList, secureDocument, secureDocument2, secureDocument3, arrayList2, str2, str3, i, runnable);
                            }
                        });
                    }

                    public /* synthetic */ void lambda$onResult$0$PassportActivity$19$1(TLRPC.TL_error error, ErrorRunnable errorRunnable, String text, TLRPC.TL_account_saveSecureValue req, boolean documentOnly, TLRPC.TL_secureRequiredType documentRequiredType, TLRPC.TL_secureRequiredType requiredType, TLRPC.TL_secureValue newValue, TLRPC.TL_secureValue newPendingValue, ArrayList documents, SecureDocument selfie, SecureDocument front, SecureDocument reverse, ArrayList translationDocuments, String json, String documentsJson, int availableDocumentTypesCount, Runnable finishRunnable) {
                        int size;
                        int size2;
                        int size3;
                        ArrayList arrayList = documents;
                        ArrayList arrayList2 = translationDocuments;
                        if (error != null) {
                            if (errorRunnable != null) {
                                errorRunnable.onError(error.text, text);
                            }
                            AlertsCreator.processError(PassportActivity.this.currentAccount, error, PassportActivity.this, req, text);
                            return;
                        }
                        if (!documentOnly) {
                            PassportActivity.this.removeValue(requiredType);
                            PassportActivity.this.removeValue(documentRequiredType);
                        } else if (documentRequiredType != null) {
                            PassportActivity.this.removeValue(documentRequiredType);
                        } else {
                            PassportActivity.this.removeValue(requiredType);
                        }
                        if (newValue != null) {
                            PassportActivity.this.currentForm.values.add(newValue);
                        }
                        if (newPendingValue != null) {
                            PassportActivity.this.currentForm.values.add(newPendingValue);
                        }
                        if (arrayList != null && !documents.isEmpty()) {
                            int a = 0;
                            int size4 = documents.size();
                            while (a < size4) {
                                SecureDocument document = (SecureDocument) arrayList.get(a);
                                if (document.inputFile == null) {
                                    size3 = size4;
                                } else {
                                    int b = 0;
                                    int size22 = newValue.files.size();
                                    while (true) {
                                        if (b >= size22) {
                                            size3 = size4;
                                            break;
                                        }
                                        int size23 = size22;
                                        TLRPC.SecureFile file = newValue.files.get(b);
                                        size3 = size4;
                                        if (file instanceof TLRPC.TL_secureFile) {
                                            TLRPC.TL_secureFile secureFile = (TLRPC.TL_secureFile) file;
                                            if (Utilities.arraysEquals(document.fileSecret, 0, secureFile.secret, 0)) {
                                                renameFile(document, secureFile);
                                                break;
                                            }
                                        }
                                        b++;
                                        size22 = size23;
                                        size4 = size3;
                                    }
                                }
                                a++;
                                arrayList = documents;
                                size4 = size3;
                            }
                        }
                        if (selfie != null && selfie.inputFile != null && (newValue.selfie instanceof TLRPC.TL_secureFile)) {
                            TLRPC.TL_secureFile secureFile2 = (TLRPC.TL_secureFile) newValue.selfie;
                            if (Utilities.arraysEquals(selfie.fileSecret, 0, secureFile2.secret, 0)) {
                                renameFile(selfie, secureFile2);
                            }
                        }
                        if (front != null && front.inputFile != null && (newValue.front_side instanceof TLRPC.TL_secureFile)) {
                            TLRPC.TL_secureFile secureFile3 = (TLRPC.TL_secureFile) newValue.front_side;
                            if (Utilities.arraysEquals(front.fileSecret, 0, secureFile3.secret, 0)) {
                                renameFile(front, secureFile3);
                            }
                        }
                        if (reverse != null && reverse.inputFile != null && (newValue.reverse_side instanceof TLRPC.TL_secureFile)) {
                            TLRPC.TL_secureFile secureFile4 = (TLRPC.TL_secureFile) newValue.reverse_side;
                            if (Utilities.arraysEquals(reverse.fileSecret, 0, secureFile4.secret, 0)) {
                                renameFile(reverse, secureFile4);
                            }
                        }
                        if (arrayList2 != null && !translationDocuments.isEmpty()) {
                            int a2 = 0;
                            int size5 = translationDocuments.size();
                            while (a2 < size5) {
                                SecureDocument document2 = (SecureDocument) arrayList2.get(a2);
                                if (document2.inputFile == null) {
                                    size = size5;
                                } else {
                                    int b2 = 0;
                                    int size24 = newValue.translation.size();
                                    while (true) {
                                        if (b2 >= size24) {
                                            size = size5;
                                            break;
                                        }
                                        TLRPC.SecureFile file2 = newValue.translation.get(b2);
                                        if (!(file2 instanceof TLRPC.TL_secureFile)) {
                                            size = size5;
                                            size2 = size24;
                                        } else {
                                            TLRPC.TL_secureFile secureFile5 = (TLRPC.TL_secureFile) file2;
                                            size = size5;
                                            size2 = size24;
                                            if (Utilities.arraysEquals(document2.fileSecret, 0, secureFile5.secret, 0)) {
                                                renameFile(document2, secureFile5);
                                                break;
                                            }
                                        }
                                        b2++;
                                        size5 = size;
                                        size24 = size2;
                                    }
                                }
                                a2++;
                                arrayList2 = translationDocuments;
                                size5 = size;
                            }
                        }
                        PassportActivity.this.setTypeValue(requiredType, text, json, documentRequiredType, documentsJson, documentOnly, availableDocumentTypesCount);
                        if (finishRunnable != null) {
                            finishRunnable.run();
                        }
                    }

                    @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                    public void run(TLObject response, final TLRPC.TL_error error) {
                        if (error != null) {
                            if (error.text.equals("EMAIL_VERIFICATION_NEEDED")) {
                                TLRPC.TL_account_sendVerifyEmailCode req = new TLRPC.TL_account_sendVerifyEmailCode();
                                req.email = this.val$text;
                                ConnectionsManager connectionsManager = ConnectionsManager.getInstance(PassportActivity.this.currentAccount);
                                final String str = this.val$text;
                                final TLRPC.TL_secureRequiredType tL_secureRequiredType = this.val$requiredType;
                                final PassportActivityDelegate passportActivityDelegate = this.val$currentDelegate;
                                final ErrorRunnable errorRunnable = this.val$errorRunnable;
                                connectionsManager.sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PassportActivity$19$1$CKkr80BeHsbCPIlXZpYYIQiS3mg
                                    @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                                    public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                                        this.f$0.lambda$run$2$PassportActivity$19$1(str, tL_secureRequiredType, passportActivityDelegate, errorRunnable, tLObject, tL_error);
                                    }
                                });
                                return;
                            }
                            if (error.text.equals("PHONE_VERIFICATION_NEEDED")) {
                                final ErrorRunnable errorRunnable2 = this.val$errorRunnable;
                                final String str2 = this.val$text;
                                AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PassportActivity$19$1$wdLhMtWuE6JMf17eo0kGtqFi8vk
                                    @Override // java.lang.Runnable
                                    public final void run() {
                                        errorRunnable2.onError(error.text, str2);
                                    }
                                });
                                return;
                            }
                        }
                        if (error == null && this.val$finalFileInputSecureValue != null) {
                            final TLRPC.TL_secureValue pendingValue = (TLRPC.TL_secureValue) response;
                            TLRPC.TL_account_saveSecureValue req2 = new TLRPC.TL_account_saveSecureValue();
                            req2.value = this.val$finalFileInputSecureValue;
                            req2.secure_secret_id = PassportActivity.this.secureSecretId;
                            ConnectionsManager.getInstance(PassportActivity.this.currentAccount).sendRequest(req2, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PassportActivity$19$1$yiQfVd9lpodkb4ZwEFf3mkprdPA
                                @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                                public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                                    this.f$0.lambda$run$4$PassportActivity$19$1(pendingValue, tLObject, tL_error);
                                }
                            });
                            return;
                        }
                        lambda$run$4$PassportActivity$19$1(error, (TLRPC.TL_secureValue) response, null);
                    }

                    public /* synthetic */ void lambda$run$2$PassportActivity$19$1(final String text, final TLRPC.TL_secureRequiredType requiredType, final PassportActivityDelegate currentDelegate, final ErrorRunnable errorRunnable, final TLObject response1, final TLRPC.TL_error error1) {
                        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PassportActivity$19$1$K2VrcwsraXjdBtNFu0zI9Ph_SQY
                            @Override // java.lang.Runnable
                            public final void run() {
                                this.f$0.lambda$null$1$PassportActivity$19$1(response1, text, requiredType, currentDelegate, error1, errorRunnable);
                            }
                        });
                    }

                    public /* synthetic */ void lambda$null$1$PassportActivity$19$1(TLObject response1, String text, TLRPC.TL_secureRequiredType requiredType, PassportActivityDelegate currentDelegate, TLRPC.TL_error error1, ErrorRunnable errorRunnable) {
                        if (response1 == null) {
                            PassportActivity.this.showAlertWithText(LocaleController.getString("PassportEmail", R.string.PassportEmail), error1.text);
                            if (errorRunnable != null) {
                                errorRunnable.onError(error1.text, text);
                                return;
                            }
                            return;
                        }
                        TLRPC.TL_account_sentEmailCode res = (TLRPC.TL_account_sentEmailCode) response1;
                        HashMap<String, String> values = new HashMap<>();
                        values.put("email", text);
                        values.put("pattern", res.email_pattern);
                        PassportActivity activity1 = new PassportActivity(6, PassportActivity.this.currentForm, PassportActivity.this.currentPassword, requiredType, (TLRPC.TL_secureValue) null, (TLRPC.TL_secureRequiredType) null, (TLRPC.TL_secureValue) null, values, (HashMap<String, String>) null);
                        activity1.currentAccount = PassportActivity.this.currentAccount;
                        activity1.emailCodeLength = res.length;
                        activity1.saltedPassword = PassportActivity.this.saltedPassword;
                        activity1.secureSecret = PassportActivity.this.secureSecret;
                        activity1.delegate = currentDelegate;
                        PassportActivity.this.presentFragment(activity1, true);
                    }
                }

                @Override // im.uwrkaxlmjj.ui.PassportActivity.PassportActivityDelegate
                public SecureDocument saveFile(TLRPC.TL_secureFile secureFile) {
                    String path = FileLoader.getDirectory(4) + "/" + secureFile.dc_id + "_" + secureFile.id + ".jpg";
                    EncryptionResult result = PassportActivity.this.createSecureDocument(path);
                    return new SecureDocument(result.secureDocumentKey, secureFile, path, result.fileHash, result.fileSecret);
                }

                @Override // im.uwrkaxlmjj.ui.PassportActivity.PassportActivityDelegate
                public void deleteValue(TLRPC.TL_secureRequiredType requiredType2, TLRPC.TL_secureRequiredType documentRequiredType2, ArrayList<TLRPC.TL_secureRequiredType> documentRequiredTypes, boolean deleteType, Runnable finishRunnable, ErrorRunnable errorRunnable) {
                    PassportActivity.this.deleteValueInternal(requiredType2, documentRequiredType2, documentRequiredTypes, deleteType, finishRunnable, errorRunnable, documentOnly);
                }
            };
            activity.currentAccount = this.currentAccount;
            activity.saltedPassword = this.saltedPassword;
            activity.secureSecret = this.secureSecret;
            activity.currentBotId = this.currentBotId;
            activity.fieldsErrors = errors;
            activity.documentOnly = documentOnly;
            activity.documentsErrors = documentsErrors;
            activity.availableDocumentTypes = availableDocumentTypes;
            if (activityType2 == 4) {
                activity.currentEmail = this.currentEmail;
            }
            presentFragment(activity);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public TLRPC.TL_secureValue removeValue(TLRPC.TL_secureRequiredType requiredType) {
        if (requiredType == null) {
            return null;
        }
        int size = this.currentForm.values.size();
        for (int a = 0; a < size; a++) {
            TLRPC.TL_secureValue secureValue = this.currentForm.values.get(a);
            if (requiredType.type.getClass() == secureValue.type.getClass()) {
                return this.currentForm.values.remove(a);
            }
        }
        return null;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void deleteValueInternal(final TLRPC.TL_secureRequiredType requiredType, final TLRPC.TL_secureRequiredType documentRequiredType, final ArrayList<TLRPC.TL_secureRequiredType> documentRequiredTypes, final boolean deleteType, final Runnable finishRunnable, final ErrorRunnable errorRunnable, final boolean documentOnly) {
        if (requiredType == null) {
            return;
        }
        TLRPC.TL_account_deleteSecureValue req = new TLRPC.TL_account_deleteSecureValue();
        if (documentOnly && documentRequiredType != null) {
            req.types.add(documentRequiredType.type);
        } else {
            if (deleteType) {
                req.types.add(requiredType.type);
            }
            if (documentRequiredType != null) {
                req.types.add(documentRequiredType.type);
            }
        }
        ConnectionsManager.getInstance(this.currentAccount).sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PassportActivity$I6A4Tdmr86xUMkqMPWVinnhCPAQ
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                this.f$0.lambda$deleteValueInternal$61$PassportActivity(errorRunnable, documentOnly, documentRequiredType, requiredType, deleteType, documentRequiredTypes, finishRunnable, tLObject, tL_error);
            }
        });
    }

    public /* synthetic */ void lambda$deleteValueInternal$61$PassportActivity(final ErrorRunnable errorRunnable, final boolean documentOnly, final TLRPC.TL_secureRequiredType documentRequiredType, final TLRPC.TL_secureRequiredType requiredType, final boolean deleteType, final ArrayList documentRequiredTypes, final Runnable finishRunnable, TLObject response, final TLRPC.TL_error error) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PassportActivity$iC7mj_TBF41wHb505b6m7dHgcqI
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$60$PassportActivity(error, errorRunnable, documentOnly, documentRequiredType, requiredType, deleteType, documentRequiredTypes, finishRunnable);
            }
        });
    }

    public /* synthetic */ void lambda$null$60$PassportActivity(TLRPC.TL_error error, ErrorRunnable errorRunnable, boolean documentOnly, TLRPC.TL_secureRequiredType documentRequiredType, TLRPC.TL_secureRequiredType requiredType, boolean deleteType, ArrayList documentRequiredTypes, Runnable finishRunnable) {
        String documentJson;
        TLRPC.TL_secureRequiredType documentsType;
        String json;
        if (error != null) {
            if (errorRunnable != null) {
                errorRunnable.onError(error.text, null);
            }
            showAlertWithText(LocaleController.getString("AppName", R.string.AppName), error.text);
            return;
        }
        if (documentOnly) {
            if (documentRequiredType != null) {
                removeValue(documentRequiredType);
            } else {
                removeValue(requiredType);
            }
        } else {
            if (deleteType) {
                removeValue(requiredType);
            }
            removeValue(documentRequiredType);
        }
        if (this.currentActivityType == 8) {
            TextDetailSecureCell view = this.typesViews.remove(requiredType);
            if (view != null) {
                this.linearLayout2.removeView(view);
                View child = this.linearLayout2.getChildAt(r1.getChildCount() - 6);
                if (child instanceof TextDetailSecureCell) {
                    ((TextDetailSecureCell) child).setNeedDivider(false);
                }
            }
            updateManageVisibility();
        } else {
            String documentJson2 = null;
            TLRPC.TL_secureRequiredType documentsType2 = documentRequiredType;
            if (documentsType2 != null && documentRequiredTypes != null && documentRequiredTypes.size() > 1) {
                int a = 0;
                int count = documentRequiredTypes.size();
                while (true) {
                    if (a >= count) {
                        break;
                    }
                    TLRPC.TL_secureRequiredType documentType = (TLRPC.TL_secureRequiredType) documentRequiredTypes.get(a);
                    TLRPC.TL_secureValue documentValue = getValueByType(documentType, false);
                    if (documentValue == null) {
                        a++;
                    } else {
                        if (documentValue.data != null) {
                            documentJson2 = decryptData(documentValue.data.data, decryptValueSecret(documentValue.data.secret, documentValue.data.data_hash), documentValue.data.data_hash);
                        }
                        documentsType2 = documentType;
                    }
                }
                if (documentsType2 != null) {
                    documentJson = documentJson2;
                    documentsType = documentsType2;
                } else {
                    documentJson = documentJson2;
                    documentsType = (TLRPC.TL_secureRequiredType) documentRequiredTypes.get(0);
                }
            } else {
                documentJson = null;
                documentsType = documentsType2;
            }
            if (deleteType) {
                setTypeValue(requiredType, null, null, documentsType, documentJson, documentOnly, documentRequiredTypes != null ? documentRequiredTypes.size() : 0);
            } else {
                TLRPC.TL_secureValue value = getValueByType(requiredType, false);
                if (value != null && value.data != null) {
                    String json2 = decryptData(value.data.data, decryptValueSecret(value.data.secret, value.data.data_hash), value.data.data_hash);
                    json = json2;
                } else {
                    json = null;
                }
                setTypeValue(requiredType, null, json, documentsType, documentJson, documentOnly, documentRequiredTypes != null ? documentRequiredTypes.size() : 0);
            }
        }
        if (finishRunnable != null) {
            finishRunnable.run();
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:61:0x01a5  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    private im.uwrkaxlmjj.ui.PassportActivity.TextDetailSecureCell addField(android.content.Context r22, final im.uwrkaxlmjj.tgnet.TLRPC.TL_secureRequiredType r23, final java.util.ArrayList<im.uwrkaxlmjj.tgnet.TLRPC.TL_secureRequiredType> r24, final boolean r25, boolean r26) {
        /*
            Method dump skipped, instruction units count: 578
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.ui.PassportActivity.addField(android.content.Context, im.uwrkaxlmjj.tgnet.TLRPC$TL_secureRequiredType, java.util.ArrayList, boolean, boolean):im.uwrkaxlmjj.ui.PassportActivity$TextDetailSecureCell");
    }

    public /* synthetic */ void lambda$addField$65$PassportActivity(final ArrayList documentRequiredTypes, final TLRPC.TL_secureRequiredType requiredType, final boolean documentOnly, View v) {
        int i;
        String str;
        TLRPC.TL_secureRequiredType documentsType = null;
        if (documentRequiredTypes != null) {
            int count = documentRequiredTypes.size();
            for (int a = 0; a < count; a++) {
                TLRPC.TL_secureRequiredType documentType = (TLRPC.TL_secureRequiredType) documentRequiredTypes.get(a);
                if (getValueByType(documentType, false) != null || count == 1) {
                    documentsType = documentType;
                    break;
                }
            }
        }
        if ((requiredType.type instanceof TLRPC.TL_secureValueTypePersonalDetails) || (requiredType.type instanceof TLRPC.TL_secureValueTypeAddress)) {
            if (documentsType == null && documentRequiredTypes != null && !documentRequiredTypes.isEmpty()) {
                AlertDialog.Builder builder = new AlertDialog.Builder(getParentActivity());
                builder.setPositiveButton(LocaleController.getString("Cancel", R.string.Cancel), null);
                if (requiredType.type instanceof TLRPC.TL_secureValueTypePersonalDetails) {
                    builder.setTitle(LocaleController.getString("PassportIdentityDocument", R.string.PassportIdentityDocument));
                } else if (requiredType.type instanceof TLRPC.TL_secureValueTypeAddress) {
                    builder.setTitle(LocaleController.getString("PassportAddress", R.string.PassportAddress));
                }
                ArrayList<String> strings = new ArrayList<>();
                int count2 = documentRequiredTypes.size();
                for (int a2 = 0; a2 < count2; a2++) {
                    TLRPC.TL_secureRequiredType documentType2 = (TLRPC.TL_secureRequiredType) documentRequiredTypes.get(a2);
                    if (documentType2.type instanceof TLRPC.TL_secureValueTypeDriverLicense) {
                        strings.add(LocaleController.getString("PassportAddLicence", R.string.PassportAddLicence));
                    } else if (documentType2.type instanceof TLRPC.TL_secureValueTypePassport) {
                        strings.add(LocaleController.getString("PassportAddPassport", R.string.PassportAddPassport));
                    } else if (documentType2.type instanceof TLRPC.TL_secureValueTypeInternalPassport) {
                        strings.add(LocaleController.getString("PassportAddInternalPassport", R.string.PassportAddInternalPassport));
                    } else if (documentType2.type instanceof TLRPC.TL_secureValueTypeIdentityCard) {
                        strings.add(LocaleController.getString("PassportAddCard", R.string.PassportAddCard));
                    } else if (documentType2.type instanceof TLRPC.TL_secureValueTypeUtilityBill) {
                        strings.add(LocaleController.getString("PassportAddBill", R.string.PassportAddBill));
                    } else if (documentType2.type instanceof TLRPC.TL_secureValueTypeBankStatement) {
                        strings.add(LocaleController.getString("PassportAddBank", R.string.PassportAddBank));
                    } else if (documentType2.type instanceof TLRPC.TL_secureValueTypeRentalAgreement) {
                        strings.add(LocaleController.getString("PassportAddAgreement", R.string.PassportAddAgreement));
                    } else if (documentType2.type instanceof TLRPC.TL_secureValueTypeTemporaryRegistration) {
                        strings.add(LocaleController.getString("PassportAddTemporaryRegistration", R.string.PassportAddTemporaryRegistration));
                    } else if (documentType2.type instanceof TLRPC.TL_secureValueTypePassportRegistration) {
                        strings.add(LocaleController.getString("PassportAddPassportRegistration", R.string.PassportAddPassportRegistration));
                    }
                }
                builder.setItems((CharSequence[]) strings.toArray(new CharSequence[0]), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PassportActivity$aNoTwSknB9JwOxop0WC7LPPMMHY
                    @Override // android.content.DialogInterface.OnClickListener
                    public final void onClick(DialogInterface dialogInterface, int i2) {
                        this.f$0.lambda$null$62$PassportActivity(requiredType, documentRequiredTypes, documentOnly, dialogInterface, i2);
                    }
                });
                showDialog(builder.create());
                return;
            }
        } else {
            boolean phoneField = requiredType.type instanceof TLRPC.TL_secureValueTypePhone;
            if (phoneField || (requiredType.type instanceof TLRPC.TL_secureValueTypeEmail)) {
                TLRPC.TL_secureValue value = getValueByType(requiredType, false);
                if (value != null) {
                    AlertDialog.Builder builder2 = new AlertDialog.Builder(getParentActivity());
                    builder2.setPositiveButton(LocaleController.getString("OK", R.string.OK), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PassportActivity$3do3AhvXtfO0VBgiTbLuXq2BRcg
                        @Override // android.content.DialogInterface.OnClickListener
                        public final void onClick(DialogInterface dialogInterface, int i2) {
                            this.f$0.lambda$null$64$PassportActivity(requiredType, documentOnly, dialogInterface, i2);
                        }
                    });
                    builder2.setNegativeButton(LocaleController.getString("Cancel", R.string.Cancel), null);
                    builder2.setTitle(LocaleController.getString("AppName", R.string.AppName));
                    if (phoneField) {
                        i = R.string.PassportDeletePhoneAlert;
                        str = "PassportDeletePhoneAlert";
                    } else {
                        i = R.string.PassportDeleteEmailAlert;
                        str = "PassportDeleteEmailAlert";
                    }
                    builder2.setMessage(LocaleController.getString(str, i));
                    showDialog(builder2.create());
                    return;
                }
            }
        }
        openTypeActivity(requiredType, documentsType, documentRequiredTypes, documentOnly);
    }

    public /* synthetic */ void lambda$null$62$PassportActivity(TLRPC.TL_secureRequiredType requiredType, ArrayList documentRequiredTypes, boolean documentOnly, DialogInterface dialog, int which) {
        openTypeActivity(requiredType, (TLRPC.TL_secureRequiredType) documentRequiredTypes.get(which), documentRequiredTypes, documentOnly);
    }

    public /* synthetic */ void lambda$null$64$PassportActivity(TLRPC.TL_secureRequiredType requiredType, boolean documentOnly, DialogInterface dialog, int which) {
        needShowProgress();
        deleteValueInternal(requiredType, null, null, true, new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$1WOh-p7phbJa9A-zippiGU5IM-c
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.needHideProgress();
            }
        }, new ErrorRunnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PassportActivity$KWjNuJtdoBJ8YBjpi8sAQG65Gv4
            @Override // im.uwrkaxlmjj.ui.PassportActivity.ErrorRunnable
            public final void onError(String str, String str2) {
                this.f$0.lambda$null$63$PassportActivity(str, str2);
            }
        }, documentOnly);
    }

    public /* synthetic */ void lambda$null$63$PassportActivity(String error, String text) {
        needHideProgress();
    }

    private class EncryptionResult {
        byte[] decrypyedFileSecret;
        byte[] encryptedData;
        byte[] fileHash;
        byte[] fileSecret;
        SecureDocumentKey secureDocumentKey;

        public EncryptionResult(byte[] d, byte[] fs, byte[] dfs, byte[] fh, byte[] fk, byte[] fi) {
            this.encryptedData = d;
            this.fileSecret = fs;
            this.fileHash = fh;
            this.decrypyedFileSecret = dfs;
            this.secureDocumentKey = new SecureDocumentKey(fk, fi);
        }
    }

    private SecureDocumentKey getSecureDocumentKey(byte[] file_secret, byte[] file_hash) {
        byte[] decrypted_file_secret = decryptValueSecret(file_secret, file_hash);
        byte[] file_secret_hash = Utilities.computeSHA512(decrypted_file_secret, file_hash);
        byte[] file_key = new byte[32];
        System.arraycopy(file_secret_hash, 0, file_key, 0, 32);
        byte[] file_iv = new byte[16];
        System.arraycopy(file_secret_hash, 32, file_iv, 0, 16);
        return new SecureDocumentKey(file_key, file_iv);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public byte[] decryptSecret(byte[] secret, byte[] passwordHash) {
        if (secret == null || secret.length != 32) {
            return null;
        }
        byte[] key = new byte[32];
        System.arraycopy(passwordHash, 0, key, 0, 32);
        byte[] iv = new byte[16];
        System.arraycopy(passwordHash, 32, iv, 0, 16);
        byte[] decryptedSecret = new byte[32];
        System.arraycopy(secret, 0, decryptedSecret, 0, 32);
        Utilities.aesCbcEncryptionByteArraySafe(decryptedSecret, key, iv, 0, decryptedSecret.length, 0, 0);
        return decryptedSecret;
    }

    private byte[] decryptValueSecret(byte[] encryptedSecureValueSecret, byte[] hash) {
        if (encryptedSecureValueSecret == null || encryptedSecureValueSecret.length != 32 || hash == null || hash.length != 32) {
            return null;
        }
        byte[] key = new byte[32];
        System.arraycopy(this.saltedPassword, 0, key, 0, 32);
        byte[] iv = new byte[16];
        System.arraycopy(this.saltedPassword, 32, iv, 0, 16);
        byte[] decryptedSecret = new byte[32];
        System.arraycopy(this.secureSecret, 0, decryptedSecret, 0, 32);
        Utilities.aesCbcEncryptionByteArraySafe(decryptedSecret, key, iv, 0, decryptedSecret.length, 0, 0);
        if (!checkSecret(decryptedSecret, null)) {
            return null;
        }
        byte[] secret_hash = Utilities.computeSHA512(decryptedSecret, hash);
        byte[] file_secret_key = new byte[32];
        System.arraycopy(secret_hash, 0, file_secret_key, 0, 32);
        byte[] file_secret_iv = new byte[16];
        System.arraycopy(secret_hash, 32, file_secret_iv, 0, 16);
        byte[] result = new byte[32];
        System.arraycopy(encryptedSecureValueSecret, 0, result, 0, 32);
        Utilities.aesCbcEncryptionByteArraySafe(result, file_secret_key, file_secret_iv, 0, result.length, 0, 0);
        return result;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public EncryptionResult createSecureDocument(String path) {
        File file = new File(path);
        int length = (int) file.length();
        byte[] b = new byte[length];
        RandomAccessFile f = null;
        try {
            f = new RandomAccessFile(path, "rws");
            f.readFully(b);
        } catch (Exception e) {
        }
        EncryptionResult result = encryptData(b);
        try {
            f.seek(0L);
            f.write(result.encryptedData);
            f.close();
        } catch (Exception e2) {
        }
        return result;
    }

    private String decryptData(byte[] data, byte[] file_secret, byte[] file_hash) {
        if (data == null || file_secret == null || file_secret.length != 32 || file_hash == null || file_hash.length != 32) {
            return null;
        }
        byte[] file_secret_hash = Utilities.computeSHA512(file_secret, file_hash);
        byte[] file_key = new byte[32];
        System.arraycopy(file_secret_hash, 0, file_key, 0, 32);
        byte[] file_iv = new byte[16];
        System.arraycopy(file_secret_hash, 32, file_iv, 0, 16);
        byte[] decryptedData = new byte[data.length];
        System.arraycopy(data, 0, decryptedData, 0, data.length);
        Utilities.aesCbcEncryptionByteArraySafe(decryptedData, file_key, file_iv, 0, decryptedData.length, 0, 0);
        byte[] hash = Utilities.computeSHA256(decryptedData);
        if (!Arrays.equals(hash, file_hash)) {
            return null;
        }
        int dataOffset = decryptedData[0] & UByte.MAX_VALUE;
        return new String(decryptedData, dataOffset, decryptedData.length - dataOffset);
    }

    public static boolean checkSecret(byte[] secret, Long id) {
        if (secret == null || secret.length != 32) {
            return false;
        }
        int sum = 0;
        for (byte b : secret) {
            sum += b & UByte.MAX_VALUE;
        }
        if (sum % 255 != 239) {
            return false;
        }
        if (id != null && Utilities.bytesToLong(Utilities.computeSHA256(secret)) != id.longValue()) {
            return false;
        }
        return true;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public byte[] getRandomSecret() {
        byte[] secret = new byte[32];
        Utilities.random.nextBytes(secret);
        int sum = 0;
        for (byte b : secret) {
            sum += b & UByte.MAX_VALUE;
        }
        int sum2 = sum % 255;
        if (sum2 != 239) {
            int a = Utilities.random.nextInt(32);
            int val = (secret[a] & UByte.MAX_VALUE) + (239 - sum2);
            if (val < 255) {
                val += 255;
            }
            secret[a] = (byte) (val % 255);
        }
        return secret;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public EncryptionResult encryptData(byte[] data) {
        byte[] file_secret = getRandomSecret();
        int extraLen = Utilities.random.nextInt(208) + 32;
        while ((data.length + extraLen) % 16 != 0) {
            extraLen++;
        }
        byte[] padding = new byte[extraLen];
        Utilities.random.nextBytes(padding);
        padding[0] = (byte) extraLen;
        byte[] paddedData = new byte[data.length + extraLen];
        System.arraycopy(padding, 0, paddedData, 0, extraLen);
        System.arraycopy(data, 0, paddedData, extraLen, data.length);
        byte[] file_hash = Utilities.computeSHA256(paddedData);
        byte[] file_secret_hash = Utilities.computeSHA512(file_secret, file_hash);
        byte[] file_key = new byte[32];
        System.arraycopy(file_secret_hash, 0, file_key, 0, 32);
        byte[] file_iv = new byte[16];
        System.arraycopy(file_secret_hash, 32, file_iv, 0, 16);
        Utilities.aesCbcEncryptionByteArraySafe(paddedData, file_key, file_iv, 0, paddedData.length, 0, 1);
        byte[] key = new byte[32];
        System.arraycopy(this.saltedPassword, 0, key, 0, 32);
        byte[] iv = new byte[16];
        System.arraycopy(this.saltedPassword, 32, iv, 0, 16);
        byte[] decryptedSecret = new byte[32];
        System.arraycopy(this.secureSecret, 0, decryptedSecret, 0, 32);
        Utilities.aesCbcEncryptionByteArraySafe(decryptedSecret, key, iv, 0, decryptedSecret.length, 0, 0);
        byte[] secret_hash = Utilities.computeSHA512(decryptedSecret, file_hash);
        byte[] file_secret_key = new byte[32];
        System.arraycopy(secret_hash, 0, file_secret_key, 0, 32);
        byte[] file_secret_iv = new byte[16];
        System.arraycopy(secret_hash, 32, file_secret_iv, 0, 16);
        byte[] encrypyed_file_secret = new byte[32];
        System.arraycopy(file_secret, 0, encrypyed_file_secret, 0, 32);
        Utilities.aesCbcEncryptionByteArraySafe(encrypyed_file_secret, file_secret_key, file_secret_iv, 0, encrypyed_file_secret.length, 0, 1);
        return new EncryptionResult(paddedData, encrypyed_file_secret, file_secret, file_hash, file_key, file_iv);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void showAlertWithText(String title, String text) {
        if (getParentActivity() == null) {
            return;
        }
        AlertDialog.Builder builder = new AlertDialog.Builder(getParentActivity());
        builder.setPositiveButton(LocaleController.getString("OK", R.string.OK), null);
        builder.setTitle(title);
        builder.setMessage(text);
        showDialog(builder.create());
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void onPasscodeError(boolean clear) {
        if (getParentActivity() == null) {
            return;
        }
        Vibrator v = (Vibrator) getParentActivity().getSystemService("vibrator");
        if (v != null) {
            v.vibrate(200L);
        }
        if (clear) {
            this.inputFields[0].setText("");
        }
        AndroidUtilities.shakeView(this.inputFields[0], 2.0f, 0);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void startPhoneVerification(boolean checkPermissions, final String phone, Runnable finishRunnable, ErrorRunnable errorRunnable, final PassportActivityDelegate delegate) {
        final TLRPC.TL_account_sendVerifyPhoneCode req = new TLRPC.TL_account_sendVerifyPhoneCode();
        req.phone_number = phone;
        req.settings = new TLRPC.TL_codeSettings();
        req.settings.allow_flashcall = false;
        req.settings.allow_app_hash = ApplicationLoader.hasPlayServices;
        SharedPreferences preferences = ApplicationLoader.applicationContext.getSharedPreferences("mainconfig", 0);
        if (req.settings.allow_app_hash) {
            preferences.edit().putString("sms_hash", BuildVars.SMS_HASH).commit();
        } else {
            preferences.edit().remove("sms_hash").commit();
        }
        ConnectionsManager.getInstance(this.currentAccount).sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PassportActivity$6R8224SEZKp5iG5DgzfAesF5_Ag
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                this.f$0.lambda$startPhoneVerification$67$PassportActivity(phone, delegate, req, tLObject, tL_error);
            }
        }, 2);
    }

    public /* synthetic */ void lambda$startPhoneVerification$67$PassportActivity(final String phone, final PassportActivityDelegate delegate, final TLRPC.TL_account_sendVerifyPhoneCode req, final TLObject response, final TLRPC.TL_error error) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PassportActivity$H1Qirzv1E5fuLJeRhBujpmVj2r8
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$66$PassportActivity(error, phone, delegate, response, req);
            }
        });
    }

    public /* synthetic */ void lambda$null$66$PassportActivity(TLRPC.TL_error error, String phone, PassportActivityDelegate delegate, TLObject response, TLRPC.TL_account_sendVerifyPhoneCode req) {
        if (error != null) {
            AlertsCreator.processError(this.currentAccount, error, this, req, phone);
            return;
        }
        HashMap<String, String> values = new HashMap<>();
        values.put("phone", phone);
        PassportActivity activity = new PassportActivity(7, this.currentForm, this.currentPassword, this.currentType, (TLRPC.TL_secureValue) null, (TLRPC.TL_secureRequiredType) null, (TLRPC.TL_secureValue) null, values, (HashMap<String, String>) null);
        activity.currentAccount = this.currentAccount;
        activity.saltedPassword = this.saltedPassword;
        activity.secureSecret = this.secureSecret;
        activity.delegate = delegate;
        activity.currentPhoneVerification = (TLRPC.TL_auth_sentCode) response;
        presentFragment(activity, true);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void updatePasswordInterface() {
        if (this.noPasswordImageView == null) {
            return;
        }
        TLRPC.TL_account_password tL_account_password = this.currentPassword;
        if (tL_account_password == null || this.usingSavedPassword != 0) {
            this.noPasswordImageView.setVisibility(8);
            this.noPasswordTextView.setVisibility(8);
            this.noPasswordSetTextView.setVisibility(8);
            this.passwordAvatarContainer.setVisibility(8);
            this.inputFieldContainers[0].setVisibility(8);
            this.doneItem.setVisibility(8);
            this.passwordForgotButton.setVisibility(8);
            this.passwordInfoRequestTextView.setVisibility(8);
            this.passwordRequestTextView.setVisibility(8);
            this.emptyView.setVisibility(0);
            return;
        }
        if (!tL_account_password.has_password) {
            this.passwordRequestTextView.setVisibility(0);
            this.noPasswordImageView.setVisibility(0);
            this.noPasswordTextView.setVisibility(0);
            this.noPasswordSetTextView.setVisibility(0);
            this.passwordAvatarContainer.setVisibility(8);
            this.inputFieldContainers[0].setVisibility(8);
            this.doneItem.setVisibility(8);
            this.passwordForgotButton.setVisibility(8);
            this.passwordInfoRequestTextView.setVisibility(8);
            this.passwordRequestTextView.setLayoutParams(LayoutHelper.createLinear(-1, -2, 0.0f, 25.0f, 0.0f, 0.0f));
            this.emptyView.setVisibility(8);
            return;
        }
        this.passwordRequestTextView.setVisibility(0);
        this.noPasswordImageView.setVisibility(8);
        this.noPasswordTextView.setVisibility(8);
        this.noPasswordSetTextView.setVisibility(8);
        this.emptyView.setVisibility(8);
        this.passwordAvatarContainer.setVisibility(0);
        this.inputFieldContainers[0].setVisibility(0);
        this.doneItem.setVisibility(0);
        this.passwordForgotButton.setVisibility(0);
        this.passwordInfoRequestTextView.setVisibility(0);
        this.passwordRequestTextView.setLayoutParams(LayoutHelper.createLinear(-1, -2, 0.0f, 0.0f, 0.0f, 0.0f));
        if (this.inputFields != null) {
            TLRPC.TL_account_password tL_account_password2 = this.currentPassword;
            if (tL_account_password2 != null && !TextUtils.isEmpty(tL_account_password2.hint)) {
                this.inputFields[0].setHint(this.currentPassword.hint);
            } else {
                this.inputFields[0].setHint(LocaleController.getString("LoginPassword", R.string.LoginPassword));
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void showEditDoneProgress(boolean animateDoneItem, final boolean show) {
        AnimatorSet animatorSet = this.doneItemAnimation;
        if (animatorSet != null) {
            animatorSet.cancel();
        }
        if (animateDoneItem && this.doneItem != null) {
            this.doneItemAnimation = new AnimatorSet();
            if (show) {
                this.progressView.setVisibility(0);
                this.doneItem.setEnabled(false);
                this.doneItemAnimation.playTogether(ObjectAnimator.ofFloat(this.doneItem.getContentView(), (Property<View, Float>) View.SCALE_X, 0.1f), ObjectAnimator.ofFloat(this.doneItem.getContentView(), (Property<View, Float>) View.SCALE_Y, 0.1f), ObjectAnimator.ofFloat(this.doneItem.getContentView(), (Property<View, Float>) View.ALPHA, 0.0f), ObjectAnimator.ofFloat(this.progressView, (Property<ContextProgressView, Float>) View.SCALE_X, 1.0f), ObjectAnimator.ofFloat(this.progressView, (Property<ContextProgressView, Float>) View.SCALE_Y, 1.0f), ObjectAnimator.ofFloat(this.progressView, (Property<ContextProgressView, Float>) View.ALPHA, 1.0f));
            } else {
                this.doneItem.getContentView().setVisibility(0);
                this.doneItem.setEnabled(true);
                this.doneItemAnimation.playTogether(ObjectAnimator.ofFloat(this.progressView, (Property<ContextProgressView, Float>) View.SCALE_X, 0.1f), ObjectAnimator.ofFloat(this.progressView, (Property<ContextProgressView, Float>) View.SCALE_Y, 0.1f), ObjectAnimator.ofFloat(this.progressView, (Property<ContextProgressView, Float>) View.ALPHA, 0.0f), ObjectAnimator.ofFloat(this.doneItem.getContentView(), (Property<View, Float>) View.SCALE_X, 1.0f), ObjectAnimator.ofFloat(this.doneItem.getContentView(), (Property<View, Float>) View.SCALE_Y, 1.0f), ObjectAnimator.ofFloat(this.doneItem.getContentView(), (Property<View, Float>) View.ALPHA, 1.0f));
            }
            this.doneItemAnimation.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.PassportActivity.20
                @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                public void onAnimationEnd(Animator animation) {
                    if (PassportActivity.this.doneItemAnimation != null && PassportActivity.this.doneItemAnimation.equals(animation)) {
                        if (!show) {
                            PassportActivity.this.progressView.setVisibility(4);
                        } else {
                            PassportActivity.this.doneItem.getContentView().setVisibility(4);
                        }
                    }
                }

                @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                public void onAnimationCancel(Animator animation) {
                    if (PassportActivity.this.doneItemAnimation != null && PassportActivity.this.doneItemAnimation.equals(animation)) {
                        PassportActivity.this.doneItemAnimation = null;
                    }
                }
            });
            this.doneItemAnimation.setDuration(150L);
            this.doneItemAnimation.start();
            return;
        }
        if (this.acceptTextView != null) {
            this.doneItemAnimation = new AnimatorSet();
            if (show) {
                this.progressViewButton.setVisibility(0);
                this.bottomLayout.setEnabled(false);
                this.doneItemAnimation.playTogether(ObjectAnimator.ofFloat(this.acceptTextView, (Property<TextView, Float>) View.SCALE_X, 0.1f), ObjectAnimator.ofFloat(this.acceptTextView, (Property<TextView, Float>) View.SCALE_Y, 0.1f), ObjectAnimator.ofFloat(this.acceptTextView, (Property<TextView, Float>) View.ALPHA, 0.0f), ObjectAnimator.ofFloat(this.progressViewButton, (Property<ContextProgressView, Float>) View.SCALE_X, 1.0f), ObjectAnimator.ofFloat(this.progressViewButton, (Property<ContextProgressView, Float>) View.SCALE_Y, 1.0f), ObjectAnimator.ofFloat(this.progressViewButton, (Property<ContextProgressView, Float>) View.ALPHA, 1.0f));
            } else {
                this.acceptTextView.setVisibility(0);
                this.bottomLayout.setEnabled(true);
                this.doneItemAnimation.playTogether(ObjectAnimator.ofFloat(this.progressViewButton, (Property<ContextProgressView, Float>) View.SCALE_X, 0.1f), ObjectAnimator.ofFloat(this.progressViewButton, (Property<ContextProgressView, Float>) View.SCALE_Y, 0.1f), ObjectAnimator.ofFloat(this.progressViewButton, (Property<ContextProgressView, Float>) View.ALPHA, 0.0f), ObjectAnimator.ofFloat(this.acceptTextView, (Property<TextView, Float>) View.SCALE_X, 1.0f), ObjectAnimator.ofFloat(this.acceptTextView, (Property<TextView, Float>) View.SCALE_Y, 1.0f), ObjectAnimator.ofFloat(this.acceptTextView, (Property<TextView, Float>) View.ALPHA, 1.0f));
            }
            this.doneItemAnimation.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.PassportActivity.21
                @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                public void onAnimationEnd(Animator animation) {
                    if (PassportActivity.this.doneItemAnimation != null && PassportActivity.this.doneItemAnimation.equals(animation)) {
                        if (!show) {
                            PassportActivity.this.progressViewButton.setVisibility(4);
                        } else {
                            PassportActivity.this.acceptTextView.setVisibility(4);
                        }
                    }
                }

                @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                public void onAnimationCancel(Animator animation) {
                    if (PassportActivity.this.doneItemAnimation != null && PassportActivity.this.doneItemAnimation.equals(animation)) {
                        PassportActivity.this.doneItemAnimation = null;
                    }
                }
            });
            this.doneItemAnimation.setDuration(150L);
            this.doneItemAnimation.start();
        }
    }

    @Override // im.uwrkaxlmjj.messenger.NotificationCenter.NotificationCenterDelegate
    public void didReceivedNotification(int id, int account, Object... args) {
        SecureDocumentCell cell;
        ActionBarMenuItem actionBarMenuItem;
        if (id == NotificationCenter.FileDidUpload) {
            String location = (String) args[0];
            SecureDocument document = this.uploadingDocuments.get(location);
            if (document != null) {
                document.inputFile = (TLRPC.TL_inputFile) args[1];
                this.uploadingDocuments.remove(location);
                if (this.uploadingDocuments.isEmpty() && (actionBarMenuItem = this.doneItem) != null) {
                    actionBarMenuItem.setEnabled(true);
                    this.doneItem.setAlpha(1.0f);
                }
                HashMap<SecureDocument, SecureDocumentCell> map = this.documentsCells;
                if (map != null && (cell = map.get(document)) != null) {
                    cell.updateButtonState(true);
                }
                HashMap<String, String> map2 = this.errorsValues;
                if (map2 != null && map2.containsKey("error_document_all")) {
                    this.errorsValues.remove("error_document_all");
                    checkTopErrorCell(false);
                }
                if (document.type == 0) {
                    if (this.bottomCell != null && !TextUtils.isEmpty(this.noAllDocumentsErrorText)) {
                        this.bottomCell.setText(this.noAllDocumentsErrorText);
                    }
                    this.errorsValues.remove("files_all");
                    return;
                }
                if (document.type == 4) {
                    if (this.bottomCellTranslation != null && !TextUtils.isEmpty(this.noAllTranslationErrorText)) {
                        this.bottomCellTranslation.setText(this.noAllTranslationErrorText);
                    }
                    this.errorsValues.remove("translation_all");
                    return;
                }
                return;
            }
            return;
        }
        if (id != NotificationCenter.FileDidFailUpload) {
            if (id == NotificationCenter.didSetTwoStepPassword) {
                if (args != null && args.length > 0) {
                    if (args[7] != null) {
                        EditTextBoldCursor[] editTextBoldCursorArr = this.inputFields;
                        if (editTextBoldCursorArr[0] != null) {
                            editTextBoldCursorArr[0].setText((String) args[7]);
                        }
                    }
                    if (args[6] == null) {
                        TLRPC.TL_account_password tL_account_password = new TLRPC.TL_account_password();
                        this.currentPassword = tL_account_password;
                        tL_account_password.current_algo = (TLRPC.PasswordKdfAlgo) args[1];
                        this.currentPassword.new_secure_algo = (TLRPC.SecurePasswordKdfAlgo) args[2];
                        this.currentPassword.secure_random = (byte[]) args[3];
                        this.currentPassword.has_recovery = !TextUtils.isEmpty((String) args[4]);
                        this.currentPassword.hint = (String) args[5];
                        this.currentPassword.srp_id = -1L;
                        this.currentPassword.srp_B = new byte[256];
                        Utilities.random.nextBytes(this.currentPassword.srp_B);
                        EditTextBoldCursor[] editTextBoldCursorArr2 = this.inputFields;
                        if (editTextBoldCursorArr2[0] != null && editTextBoldCursorArr2[0].length() > 0) {
                            this.usingSavedPassword = 2;
                        }
                    }
                } else {
                    this.currentPassword = null;
                    loadPasswordInfo();
                }
                updatePasswordInterface();
                return;
            }
            int i = NotificationCenter.didRemoveTwoStepPassword;
        }
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onTransitionAnimationEnd(boolean isOpen, boolean backward) {
        if (this.presentAfterAnimation != null) {
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PassportActivity$dlPtSt32Rq80UypNj3Fakn1tnjA
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$onTransitionAnimationEnd$68$PassportActivity();
                }
            });
        }
        int i = this.currentActivityType;
        if (i == 5) {
            if (isOpen) {
                if (this.inputFieldContainers[0].getVisibility() == 0) {
                    this.inputFields[0].requestFocus();
                    AndroidUtilities.showKeyboard(this.inputFields[0]);
                }
                if (this.usingSavedPassword == 2) {
                    onPasswordDone(false);
                    return;
                }
                return;
            }
            return;
        }
        if (i == 7) {
            if (isOpen) {
                this.views[this.currentViewNum].onShow();
                return;
            }
            return;
        }
        if (i == 4) {
            if (isOpen) {
                this.inputFields[0].requestFocus();
                AndroidUtilities.showKeyboard(this.inputFields[0]);
                return;
            }
            return;
        }
        if (i == 6) {
            if (isOpen) {
                this.inputFields[0].requestFocus();
                AndroidUtilities.showKeyboard(this.inputFields[0]);
                return;
            }
            return;
        }
        if ((i == 2 || i == 1) && Build.VERSION.SDK_INT >= 21) {
            createChatAttachView();
        }
    }

    public /* synthetic */ void lambda$onTransitionAnimationEnd$68$PassportActivity() {
        presentFragment(this.presentAfterAnimation, true);
        this.presentAfterAnimation = null;
    }

    private void showAttachmentError() {
        if (getParentActivity() == null) {
            return;
        }
        ToastUtils.show(R.string.UnsupportedAttachment);
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onActivityResultFragment(int requestCode, int resultCode, Intent data) {
        if (resultCode == -1) {
            if (requestCode == 0 || requestCode == 2) {
                createChatAttachView();
                ChatAttachAlert chatAttachAlert = this.chatAttachAlert;
                if (chatAttachAlert != null) {
                    chatAttachAlert.onActivityResultFragment(requestCode, data, this.currentPicturePath);
                }
                this.currentPicturePath = null;
                return;
            }
            if (requestCode == 1) {
                if (data == null || data.getData() == null) {
                    showAttachmentError();
                    return;
                }
                ArrayList<SendMessagesHelper.SendingMediaInfo> photos = new ArrayList<>();
                SendMessagesHelper.SendingMediaInfo info = new SendMessagesHelper.SendingMediaInfo();
                info.uri = data.getData();
                photos.add(info);
                processSelectedFiles(photos);
            }
        }
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onRequestPermissionsResultFragment(int requestCode, String[] permissions, int[] grantResults) {
        ChatAttachAlert chatAttachAlert;
        TextSettingsCell textSettingsCell;
        int i = this.currentActivityType;
        if ((i == 1 || i == 2) && (chatAttachAlert = this.chatAttachAlert) != null) {
            if (requestCode == 17 && chatAttachAlert != null) {
                chatAttachAlert.checkCamera(false);
                return;
            }
            if (requestCode == 21) {
                if (getParentActivity() != null && grantResults != null && grantResults.length != 0 && grantResults[0] != 0) {
                    AlertDialog.Builder builder = new AlertDialog.Builder(getParentActivity());
                    builder.setTitle(LocaleController.getString("AppName", R.string.AppName));
                    builder.setMessage(LocaleController.getString("PermissionNoAudioVideo", R.string.PermissionNoAudioVideo));
                    builder.setNegativeButton(LocaleController.getString("PermissionOpenSettings", R.string.PermissionOpenSettings), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PassportActivity$UXUergpSpRJQwbBYKIN9sis54Nk
                        @Override // android.content.DialogInterface.OnClickListener
                        public final void onClick(DialogInterface dialogInterface, int i2) {
                            this.f$0.lambda$onRequestPermissionsResultFragment$69$PassportActivity(dialogInterface, i2);
                        }
                    });
                    builder.setPositiveButton(LocaleController.getString("OK", R.string.OK), null);
                    builder.show();
                    return;
                }
                return;
            }
            if (requestCode == 19 && grantResults != null && grantResults.length > 0 && grantResults[0] == 0) {
                processSelectedAttach(0);
                return;
            }
            if (requestCode == 22 && grantResults != null && grantResults.length > 0 && grantResults[0] == 0 && (textSettingsCell = this.scanDocumentCell) != null) {
                textSettingsCell.callOnClick();
                return;
            }
            return;
        }
        if (this.currentActivityType == 3 && requestCode == 6) {
            startPhoneVerification(false, this.pendingPhone, this.pendingFinishRunnable, this.pendingErrorRunnable, this.pendingDelegate);
        }
    }

    public /* synthetic */ void lambda$onRequestPermissionsResultFragment$69$PassportActivity(DialogInterface dialog, int which) {
        try {
            Intent intent = new Intent("android.settings.APPLICATION_DETAILS_SETTINGS");
            intent.setData(Uri.parse("package:" + ApplicationLoader.applicationContext.getPackageName()));
            getParentActivity().startActivity(intent);
        } catch (Exception e) {
            FileLog.e(e);
        }
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void saveSelfArgs(Bundle args) {
        String str = this.currentPicturePath;
        if (str != null) {
            args.putString("path", str);
        }
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void restoreSelfArgs(Bundle args) {
        this.currentPicturePath = args.getString("path");
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public boolean onBackPressed() {
        int i = this.currentActivityType;
        if (i == 7) {
            this.views[this.currentViewNum].onBackPressed(true);
            int a = 0;
            while (true) {
                SlideView[] slideViewArr = this.views;
                if (a >= slideViewArr.length) {
                    break;
                }
                if (slideViewArr[a] != null) {
                    slideViewArr[a].onDestroyActivity();
                }
                a++;
            }
        } else if (i == 0 || i == 5) {
            callCallback(false);
        } else if (i == 1 || i == 2) {
            return !checkDiscard();
        }
        return true;
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    protected void onDialogDismiss(Dialog dialog) {
        if (this.currentActivityType == 3 && Build.VERSION.SDK_INT >= 23 && dialog == this.permissionsDialog && !this.permissionsItems.isEmpty()) {
            getParentActivity().requestPermissions((String[]) this.permissionsItems.toArray(new String[0]), 6);
        }
    }

    public void needShowProgress() {
        if (getParentActivity() == null || getParentActivity().isFinishing() || this.progressDialog != null) {
            return;
        }
        AlertDialog alertDialog = new AlertDialog(getParentActivity(), 3);
        this.progressDialog = alertDialog;
        alertDialog.setCanCancel(false);
        this.progressDialog.show();
    }

    public void needHideProgress() {
        AlertDialog alertDialog = this.progressDialog;
        if (alertDialog == null) {
            return;
        }
        try {
            alertDialog.dismiss();
        } catch (Exception e) {
            FileLog.e(e);
        }
        this.progressDialog = null;
    }

    public void setPage(int page, boolean animated, Bundle params) {
        if (page == 3) {
            this.doneItem.setVisibility(8);
        }
        SlideView[] slideViewArr = this.views;
        final SlideView outView = slideViewArr[this.currentViewNum];
        final SlideView newView = slideViewArr[page];
        this.currentViewNum = page;
        newView.setParams(params, false);
        newView.onShow();
        if (animated) {
            newView.setTranslationX(AndroidUtilities.displaySize.x);
            AnimatorSet animatorSet = new AnimatorSet();
            animatorSet.setInterpolator(new AccelerateDecelerateInterpolator());
            animatorSet.setDuration(300L);
            animatorSet.playTogether(ObjectAnimator.ofFloat(outView, "translationX", -AndroidUtilities.displaySize.x), ObjectAnimator.ofFloat(newView, "translationX", 0.0f));
            animatorSet.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.PassportActivity.22
                @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                public void onAnimationStart(Animator animation) {
                    newView.setVisibility(0);
                }

                @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                public void onAnimationEnd(Animator animation) {
                    outView.setVisibility(8);
                    outView.setX(0.0f);
                }
            });
            animatorSet.start();
            return;
        }
        newView.setTranslationX(0.0f);
        newView.setVisibility(0);
        if (outView != newView) {
            outView.setVisibility(8);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void fillNextCodeParams(Bundle params, TLRPC.TL_auth_sentCode res, boolean animated) {
        params.putString("phoneHash", res.phone_code_hash);
        if (res.next_type instanceof TLRPC.TL_auth_codeTypeCall) {
            params.putInt("nextType", 4);
        } else if (res.next_type instanceof TLRPC.TL_auth_codeTypeFlashCall) {
            params.putInt("nextType", 3);
        } else if (res.next_type instanceof TLRPC.TL_auth_codeTypeSms) {
            params.putInt("nextType", 2);
        }
        if (res.timeout == 0) {
            res.timeout = 60;
        }
        params.putInt("timeout", res.timeout * 1000);
        if (res.type instanceof TLRPC.TL_auth_sentCodeTypeCall) {
            params.putInt("type", 4);
            params.putInt("length", res.type.length);
            setPage(2, animated, params);
        } else if (res.type instanceof TLRPC.TL_auth_sentCodeTypeFlashCall) {
            params.putInt("type", 3);
            params.putString("pattern", res.type.pattern);
            setPage(1, animated, params);
        } else if (res.type instanceof TLRPC.TL_auth_sentCodeTypeSms) {
            params.putInt("type", 2);
            params.putInt("length", res.type.length);
            setPage(0, animated, params);
        }
    }

    private void openAttachMenu() {
        if (getParentActivity() == null) {
            return;
        }
        if (this.uploadingFileType == 0 && this.documents.size() >= 20) {
            showAlertWithText(LocaleController.getString("AppName", R.string.AppName), LocaleController.formatString("PassportUploadMaxReached", R.string.PassportUploadMaxReached, LocaleController.formatPluralString("Files", 20)));
            return;
        }
        createChatAttachView();
        this.chatAttachAlert.setOpenWithFrontFaceCamera(this.uploadingFileType == 1);
        this.chatAttachAlert.setMaxSelectedPhotos(getMaxSelectedDocuments(), false);
        this.chatAttachAlert.loadGalleryPhotos();
        if (Build.VERSION.SDK_INT == 21 || Build.VERSION.SDK_INT == 22) {
            AndroidUtilities.hideKeyboard(this.fragmentView.findFocus());
        }
        this.chatAttachAlert.init();
        showDialog(this.chatAttachAlert);
    }

    private void createChatAttachView() {
        if (getParentActivity() != null && this.chatAttachAlert == null) {
            ChatAttachAlert chatAttachAlert = new ChatAttachAlert(getParentActivity(), this);
            this.chatAttachAlert = chatAttachAlert;
            chatAttachAlert.setDelegate(new ChatAttachAlert.ChatAttachViewDelegate() { // from class: im.uwrkaxlmjj.ui.PassportActivity.23
                @Override // im.uwrkaxlmjj.ui.components.ChatAttachAlert.ChatAttachViewDelegate
                public void didPressedButton(int button, boolean arg, boolean notify, int scheduleDate) {
                    if (PassportActivity.this.getParentActivity() == null || PassportActivity.this.chatAttachAlert == null) {
                        return;
                    }
                    if (button != 8 && button != 7) {
                        if (PassportActivity.this.chatAttachAlert != null) {
                            PassportActivity.this.chatAttachAlert.dismissWithButtonClick(button);
                        }
                        PassportActivity.this.processSelectedAttach(button);
                        return;
                    }
                    if (button != 8) {
                        PassportActivity.this.chatAttachAlert.dismiss();
                    }
                    HashMap<Object, Object> selectedPhotos = PassportActivity.this.chatAttachAlert.getSelectedPhotos();
                    ArrayList<Object> selectedPhotosOrder = PassportActivity.this.chatAttachAlert.getSelectedPhotosOrder();
                    if (!selectedPhotos.isEmpty()) {
                        ArrayList<SendMessagesHelper.SendingMediaInfo> photos = new ArrayList<>();
                        for (int a = 0; a < selectedPhotosOrder.size(); a++) {
                            MediaController.PhotoEntry photoEntry = (MediaController.PhotoEntry) selectedPhotos.get(selectedPhotosOrder.get(a));
                            SendMessagesHelper.SendingMediaInfo info = new SendMessagesHelper.SendingMediaInfo();
                            if (photoEntry.imagePath != null) {
                                info.path = photoEntry.imagePath;
                            } else if (photoEntry.path != null) {
                                info.path = photoEntry.path;
                            }
                            photos.add(info);
                            photoEntry.reset();
                        }
                        PassportActivity.this.processSelectedFiles(photos);
                    }
                }

                @Override // im.uwrkaxlmjj.ui.components.ChatAttachAlert.ChatAttachViewDelegate
                public View getRevealView() {
                    return null;
                }

                @Override // im.uwrkaxlmjj.ui.components.ChatAttachAlert.ChatAttachViewDelegate
                public void didSelectBot(TLRPC.User user) {
                }

                @Override // im.uwrkaxlmjj.ui.components.ChatAttachAlert.ChatAttachViewDelegate
                public void onCameraOpened() {
                    AndroidUtilities.hideKeyboard(PassportActivity.this.fragmentView.findFocus());
                }

                @Override // im.uwrkaxlmjj.ui.components.ChatAttachAlert.ChatAttachViewDelegate
                public void needEnterComment() {
                }
            });
        }
    }

    private int getMaxSelectedDocuments() {
        int i = this.uploadingFileType;
        if (i == 0) {
            return 20 - this.documents.size();
        }
        if (i == 4) {
            return 20 - this.translationDocuments.size();
        }
        return 1;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void processSelectedAttach(int which) {
        if (which == 0) {
            if (Build.VERSION.SDK_INT >= 23 && getParentActivity().checkSelfPermission("android.permission.CAMERA") != 0) {
                getParentActivity().requestPermissions(new String[]{"android.permission.CAMERA"}, 19);
                return;
            }
            try {
                Intent takePictureIntent = new Intent("android.media.action.IMAGE_CAPTURE");
                File image = AndroidUtilities.generatePicturePath();
                if (image != null) {
                    if (Build.VERSION.SDK_INT >= 24) {
                        takePictureIntent.putExtra("output", FileProvider.getUriForFile(getParentActivity(), "singansfg.uwrkaxlmjj.sdancsuhsfj.provider", image));
                        takePictureIntent.addFlags(2);
                        takePictureIntent.addFlags(1);
                    } else {
                        takePictureIntent.putExtra("output", Uri.fromFile(image));
                    }
                    this.currentPicturePath = image.getAbsolutePath();
                }
                startActivityForResult(takePictureIntent, 0);
                return;
            } catch (Exception e) {
                FileLog.e(e);
                return;
            }
        }
        if (which == 1) {
            if (Build.VERSION.SDK_INT >= 23 && getParentActivity().checkSelfPermission(PermissionUtils.PERMISSION_READ_EXTERNAL_STORAGE) != 0) {
                getParentActivity().requestPermissions(new String[]{PermissionUtils.PERMISSION_READ_EXTERNAL_STORAGE}, 4);
                return;
            }
            PhotoAlbumPickerActivity fragment = new PhotoAlbumPickerActivity(0, false, false, null);
            fragment.setCurrentAccount(this.currentAccount);
            fragment.setMaxSelectedPhotos(getMaxSelectedDocuments(), false);
            fragment.setAllowSearchImages(false);
            fragment.setDelegate(new PhotoAlbumPickerActivity.PhotoAlbumPickerActivityDelegate() { // from class: im.uwrkaxlmjj.ui.PassportActivity.24
                @Override // im.uwrkaxlmjj.ui.PhotoAlbumPickerActivity.PhotoAlbumPickerActivityDelegate
                public void didSelectPhotos(ArrayList<SendMessagesHelper.SendingMediaInfo> photos, boolean notify, int scheduleDate, boolean blnOriginalImg) {
                    PassportActivity.this.processSelectedFiles(photos);
                }

                @Override // im.uwrkaxlmjj.ui.PhotoAlbumPickerActivity.PhotoAlbumPickerActivityDelegate
                public void startPhotoSelectActivity() {
                    try {
                        Intent photoPickerIntent = new Intent("android.intent.action.PICK");
                        photoPickerIntent.setType("image/*");
                        PassportActivity.this.startActivityForResult(photoPickerIntent, 1);
                    } catch (Exception e2) {
                        FileLog.e(e2);
                    }
                }
            });
            presentFragment(fragment);
            return;
        }
        if (which == 4) {
            if (Build.VERSION.SDK_INT >= 23 && getParentActivity().checkSelfPermission(PermissionUtils.PERMISSION_READ_EXTERNAL_STORAGE) != 0) {
                getParentActivity().requestPermissions(new String[]{PermissionUtils.PERMISSION_READ_EXTERNAL_STORAGE}, 4);
                return;
            }
            DocumentSelectActivity fragment2 = new DocumentSelectActivity(false);
            fragment2.setCurrentAccount(this.currentAccount);
            fragment2.setCanSelectOnlyImageFiles(true);
            fragment2.setMaxSelectedFiles(getMaxSelectedDocuments());
            fragment2.setDelegate(new DocumentSelectActivity.DocumentSelectActivityDelegate() { // from class: im.uwrkaxlmjj.ui.PassportActivity.25
                @Override // im.uwrkaxlmjj.ui.DocumentSelectActivity.DocumentSelectActivityDelegate
                public /* synthetic */ void startMusicSelectActivity(BaseFragment baseFragment) {
                    DocumentSelectActivity.DocumentSelectActivityDelegate.CC.$default$startMusicSelectActivity(this, baseFragment);
                }

                @Override // im.uwrkaxlmjj.ui.DocumentSelectActivity.DocumentSelectActivityDelegate
                public void didSelectFiles(DocumentSelectActivity activity, ArrayList<String> files, boolean notify, int scheduleDate) {
                    activity.finishFragment();
                    ArrayList<SendMessagesHelper.SendingMediaInfo> arrayList = new ArrayList<>();
                    int count = files.size();
                    for (int a = 0; a < count; a++) {
                        SendMessagesHelper.SendingMediaInfo info = new SendMessagesHelper.SendingMediaInfo();
                        info.path = files.get(a);
                        arrayList.add(info);
                    }
                    PassportActivity.this.processSelectedFiles(arrayList);
                }

                @Override // im.uwrkaxlmjj.ui.DocumentSelectActivity.DocumentSelectActivityDelegate
                public void startDocumentSelectActivity() {
                    try {
                        Intent photoPickerIntent = new Intent("android.intent.action.GET_CONTENT");
                        if (Build.VERSION.SDK_INT >= 18) {
                            photoPickerIntent.putExtra("android.intent.extra.ALLOW_MULTIPLE", true);
                        }
                        photoPickerIntent.setType("*/*");
                        PassportActivity.this.startActivityForResult(photoPickerIntent, 21);
                    } catch (Exception e2) {
                        FileLog.e(e2);
                    }
                }
            });
            presentFragment(fragment2);
        }
    }

    private void fillInitialValues() {
        if (this.initialValues != null) {
            return;
        }
        this.initialValues = getCurrentValues();
    }

    private String getCurrentValues() {
        StringBuilder values = new StringBuilder();
        int a = 0;
        while (true) {
            EditTextBoldCursor[] editTextBoldCursorArr = this.inputFields;
            if (a >= editTextBoldCursorArr.length) {
                break;
            }
            values.append((CharSequence) editTextBoldCursorArr[a].getText());
            values.append(",");
            a++;
        }
        if (this.inputExtraFields != null) {
            int a2 = 0;
            while (true) {
                EditTextBoldCursor[] editTextBoldCursorArr2 = this.inputExtraFields;
                if (a2 >= editTextBoldCursorArr2.length) {
                    break;
                }
                values.append((CharSequence) editTextBoldCursorArr2[a2].getText());
                values.append(",");
                a2++;
            }
        }
        int count = this.documents.size();
        for (int a3 = 0; a3 < count; a3++) {
            values.append(this.documents.get(a3).secureFile.id);
        }
        SecureDocument secureDocument = this.frontDocument;
        if (secureDocument != null) {
            values.append(secureDocument.secureFile.id);
        }
        SecureDocument secureDocument2 = this.reverseDocument;
        if (secureDocument2 != null) {
            values.append(secureDocument2.secureFile.id);
        }
        SecureDocument secureDocument3 = this.selfieDocument;
        if (secureDocument3 != null) {
            values.append(secureDocument3.secureFile.id);
        }
        int count2 = this.translationDocuments.size();
        for (int a4 = 0; a4 < count2; a4++) {
            values.append(this.translationDocuments.get(a4).secureFile.id);
        }
        return values.toString();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public boolean isHasNotAnyChanges() {
        String str = this.initialValues;
        return str == null || str.equals(getCurrentValues());
    }

    /* JADX INFO: Access modifiers changed from: private */
    public boolean checkDiscard() {
        if (isHasNotAnyChanges()) {
            return false;
        }
        AlertDialog.Builder builder = new AlertDialog.Builder(getParentActivity());
        builder.setPositiveButton(LocaleController.getString("PassportDiscard", R.string.PassportDiscard), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PassportActivity$tbUbT33XZoMh2u4KKWSSavx5J9I
            @Override // android.content.DialogInterface.OnClickListener
            public final void onClick(DialogInterface dialogInterface, int i) {
                this.f$0.lambda$checkDiscard$70$PassportActivity(dialogInterface, i);
            }
        });
        builder.setNegativeButton(LocaleController.getString("Cancel", R.string.Cancel), null);
        builder.setTitle(LocaleController.getString("DiscardChanges", R.string.DiscardChanges));
        builder.setMessage(LocaleController.getString("PassportDiscardChanges", R.string.PassportDiscardChanges));
        showDialog(builder.create());
        return true;
    }

    public /* synthetic */ void lambda$checkDiscard$70$PassportActivity(DialogInterface dialog, int which) {
        finishFragment();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void processSelectedFiles(final ArrayList<SendMessagesHelper.SendingMediaInfo> photos) {
        final boolean allFieldsAreEmpty;
        if (photos.isEmpty()) {
            return;
        }
        int i = this.uploadingFileType;
        if (i != 1 && i != 4 && (this.currentType.type instanceof TLRPC.TL_secureValueTypePersonalDetails)) {
            allFieldsAreEmpty = true;
            int a = 0;
            while (true) {
                EditTextBoldCursor[] editTextBoldCursorArr = this.inputFields;
                if (a < editTextBoldCursorArr.length) {
                    if (a == 5 || a == 8 || a == 4 || a == 6 || editTextBoldCursorArr[a].length() <= 0) {
                        a++;
                    } else {
                        allFieldsAreEmpty = false;
                        break;
                    }
                } else {
                    break;
                }
            }
        } else {
            allFieldsAreEmpty = false;
        }
        final int type = this.uploadingFileType;
        Utilities.globalQueue.postRunnable(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PassportActivity$Nm9ONL5MuC0c0GTOTUsUTE-gI_c
            @Override // java.lang.Runnable
            public final void run() throws FileNotFoundException {
                this.f$0.lambda$processSelectedFiles$73$PassportActivity(photos, type, allFieldsAreEmpty);
            }
        });
    }

    public /* synthetic */ void lambda$processSelectedFiles$73$PassportActivity(ArrayList photos, final int type, boolean needRecoginze) throws FileNotFoundException {
        TLRPC.PhotoSize size;
        int i = this.uploadingFileType;
        int count = Math.min((i == 0 || i == 4) ? 20 : 1, photos.size());
        int a = 0;
        for (int a2 = 0; a2 < count; a2++) {
            SendMessagesHelper.SendingMediaInfo info = (SendMessagesHelper.SendingMediaInfo) photos.get(a2);
            Bitmap bitmap = ImageLoader.loadBitmap(info.path, info.uri, 2048.0f, 2048.0f, false);
            if (bitmap != null && (size = ImageLoader.scaleAndSaveImage(bitmap, 2048.0f, 2048.0f, 89, false, 320, 320)) != null) {
                TLRPC.TL_secureFile secureFile = new TLRPC.TL_secureFile();
                secureFile.dc_id = (int) size.location.volume_id;
                secureFile.id = size.location.local_id;
                secureFile.date = (int) (System.currentTimeMillis() / 1000);
                final SecureDocument document = this.delegate.saveFile(secureFile);
                document.type = type;
                AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PassportActivity$Kj0t0bW5p_mVp-gcYmKMjePwhbo
                    @Override // java.lang.Runnable
                    public final void run() {
                        this.f$0.lambda$null$71$PassportActivity(document, type);
                    }
                });
                if (needRecoginze && a == 0) {
                    try {
                        final MrzRecognizer.Result result = MrzRecognizer.recognize(bitmap, this.currentDocumentsType.type instanceof TLRPC.TL_secureValueTypeDriverLicense);
                        if (result != null) {
                            a = 1;
                            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PassportActivity$ictT3cgnf5kUl65PI00e1uwJBJU
                                @Override // java.lang.Runnable
                                public final void run() {
                                    this.f$0.lambda$null$72$PassportActivity(result);
                                }
                            });
                        }
                    } catch (Throwable e) {
                        FileLog.e(e);
                    }
                }
            }
        }
        SharedConfig.saveConfig();
    }

    public /* synthetic */ void lambda$null$71$PassportActivity(SecureDocument document, int type) {
        int i = this.uploadingFileType;
        if (i == 1) {
            SecureDocument secureDocument = this.selfieDocument;
            if (secureDocument != null) {
                SecureDocumentCell cell = this.documentsCells.remove(secureDocument);
                if (cell != null) {
                    this.selfieLayout.removeView(cell);
                }
                this.selfieDocument = null;
            }
        } else if (i == 4) {
            if (this.translationDocuments.size() >= 20) {
                return;
            }
        } else if (i == 2) {
            SecureDocument secureDocument2 = this.frontDocument;
            if (secureDocument2 != null) {
                SecureDocumentCell cell2 = this.documentsCells.remove(secureDocument2);
                if (cell2 != null) {
                    this.frontLayout.removeView(cell2);
                }
                this.frontDocument = null;
            }
        } else if (i == 3) {
            SecureDocument secureDocument3 = this.reverseDocument;
            if (secureDocument3 != null) {
                SecureDocumentCell cell3 = this.documentsCells.remove(secureDocument3);
                if (cell3 != null) {
                    this.reverseLayout.removeView(cell3);
                }
                this.reverseDocument = null;
            }
        } else if (i == 0 && this.documents.size() >= 20) {
            return;
        }
        this.uploadingDocuments.put(document.path, document);
        this.doneItem.setEnabled(false);
        this.doneItem.setAlpha(0.5f);
        FileLoader.getInstance(this.currentAccount).uploadFile(document.path, false, true, 16777216);
        addDocumentView(document, type);
        updateUploadText(type);
    }

    public /* synthetic */ void lambda$null$72$PassportActivity(MrzRecognizer.Result result) {
        if (result.type == 2) {
            if (!(this.currentDocumentsType.type instanceof TLRPC.TL_secureValueTypeIdentityCard)) {
                int a1 = 0;
                int count1 = this.availableDocumentTypes.size();
                while (true) {
                    if (a1 >= count1) {
                        break;
                    }
                    TLRPC.TL_secureRequiredType requiredType = this.availableDocumentTypes.get(a1);
                    if (!(requiredType.type instanceof TLRPC.TL_secureValueTypeIdentityCard)) {
                        a1++;
                    } else {
                        this.currentDocumentsType = requiredType;
                        updateInterfaceStringsForDocumentType();
                        break;
                    }
                }
            }
        } else if (result.type == 1) {
            if (!(this.currentDocumentsType.type instanceof TLRPC.TL_secureValueTypePassport)) {
                int a12 = 0;
                int count12 = this.availableDocumentTypes.size();
                while (true) {
                    if (a12 >= count12) {
                        break;
                    }
                    TLRPC.TL_secureRequiredType requiredType2 = this.availableDocumentTypes.get(a12);
                    if (!(requiredType2.type instanceof TLRPC.TL_secureValueTypePassport)) {
                        a12++;
                    } else {
                        this.currentDocumentsType = requiredType2;
                        updateInterfaceStringsForDocumentType();
                        break;
                    }
                }
            }
        } else if (result.type == 3) {
            if (!(this.currentDocumentsType.type instanceof TLRPC.TL_secureValueTypeInternalPassport)) {
                int a13 = 0;
                int count13 = this.availableDocumentTypes.size();
                while (true) {
                    if (a13 >= count13) {
                        break;
                    }
                    TLRPC.TL_secureRequiredType requiredType3 = this.availableDocumentTypes.get(a13);
                    if (!(requiredType3.type instanceof TLRPC.TL_secureValueTypeInternalPassport)) {
                        a13++;
                    } else {
                        this.currentDocumentsType = requiredType3;
                        updateInterfaceStringsForDocumentType();
                        break;
                    }
                }
            }
        } else if (result.type == 4 && !(this.currentDocumentsType.type instanceof TLRPC.TL_secureValueTypeDriverLicense)) {
            int a14 = 0;
            int count14 = this.availableDocumentTypes.size();
            while (true) {
                if (a14 >= count14) {
                    break;
                }
                TLRPC.TL_secureRequiredType requiredType4 = this.availableDocumentTypes.get(a14);
                if (!(requiredType4.type instanceof TLRPC.TL_secureValueTypeDriverLicense)) {
                    a14++;
                } else {
                    this.currentDocumentsType = requiredType4;
                    updateInterfaceStringsForDocumentType();
                    break;
                }
            }
        }
        if (!TextUtils.isEmpty(result.firstName)) {
            this.inputFields[0].setText(result.firstName);
        }
        if (!TextUtils.isEmpty(result.middleName)) {
            this.inputFields[1].setText(result.middleName);
        }
        if (!TextUtils.isEmpty(result.lastName)) {
            this.inputFields[2].setText(result.lastName);
        }
        if (!TextUtils.isEmpty(result.number)) {
            this.inputFields[7].setText(result.number);
        }
        if (result.gender != 0) {
            int i = result.gender;
            if (i == 1) {
                this.currentGender = "male";
                this.inputFields[4].setText(LocaleController.getString("PassportMale", R.string.PassportMale));
            } else if (i == 2) {
                this.currentGender = "female";
                this.inputFields[4].setText(LocaleController.getString("PassportFemale", R.string.PassportFemale));
            }
        }
        if (!TextUtils.isEmpty(result.nationality)) {
            String str = result.nationality;
            this.currentCitizeship = str;
            String country = this.languageMap.get(str);
            if (country != null) {
                this.inputFields[5].setText(country);
            }
        }
        if (!TextUtils.isEmpty(result.issuingCountry)) {
            String str2 = result.issuingCountry;
            this.currentResidence = str2;
            String country2 = this.languageMap.get(str2);
            if (country2 != null) {
                this.inputFields[6].setText(country2);
            }
        }
        if (result.birthDay > 0 && result.birthMonth > 0 && result.birthYear > 0) {
            this.inputFields[3].setText(String.format(Locale.US, "%02d.%02d.%d", Integer.valueOf(result.birthDay), Integer.valueOf(result.birthMonth), Integer.valueOf(result.birthYear)));
        }
        if (result.expiryDay > 0 && result.expiryMonth > 0 && result.expiryYear > 0) {
            this.currentExpireDate[0] = result.expiryYear;
            this.currentExpireDate[1] = result.expiryMonth;
            this.currentExpireDate[2] = result.expiryDay;
            this.inputFields[8].setText(String.format(Locale.US, "%02d.%02d.%d", Integer.valueOf(result.expiryDay), Integer.valueOf(result.expiryMonth), Integer.valueOf(result.expiryYear)));
            return;
        }
        int[] iArr = this.currentExpireDate;
        iArr[2] = 0;
        iArr[1] = 0;
        iArr[0] = 0;
        this.inputFields[8].setText(LocaleController.getString("PassportNoExpireDate", R.string.PassportNoExpireDate));
    }

    public void setNeedActivityResult(boolean needActivityResult) {
        this.needActivityResult = needActivityResult;
    }

    private class ProgressView extends View {
        private Paint paint;
        private Paint paint2;
        private float progress;

        public ProgressView(Context context) {
            super(context);
            this.paint = new Paint();
            this.paint2 = new Paint();
            this.paint.setColor(Theme.getColor(Theme.key_login_progressInner));
            this.paint2.setColor(Theme.getColor(Theme.key_login_progressOuter));
        }

        public void setProgress(float value) {
            this.progress = value;
            invalidate();
        }

        @Override // android.view.View
        protected void onDraw(Canvas canvas) {
            int start = (int) (getMeasuredWidth() * this.progress);
            canvas.drawRect(0.0f, 0.0f, start, getMeasuredHeight(), this.paint2);
            canvas.drawRect(start, 0.0f, getMeasuredWidth(), getMeasuredHeight(), this.paint);
        }
    }

    public class PhoneConfirmationView extends SlideView implements NotificationCenter.NotificationCenterDelegate {
        private ImageView blackImageView;
        private ImageView blueImageView;
        private EditTextBoldCursor[] codeField;
        private LinearLayout codeFieldContainer;
        private int codeTime;
        private Timer codeTimer;
        private TextView confirmTextView;
        private Bundle currentParams;
        private boolean ignoreOnTextChange;
        private double lastCodeTime;
        private double lastCurrentTime;
        private String lastError;
        private int length;
        private boolean nextPressed;
        private int nextType;
        private int openTime;
        private String pattern;
        private String phone;
        private String phoneHash;
        private TextView problemText;
        private ProgressView progressView;
        private int time;
        private TextView timeText;
        private Timer timeTimer;
        private int timeout;
        private final Object timerSync;
        private TextView titleTextView;
        private int verificationType;
        private boolean waitingForEvent;

        public PhoneConfirmationView(Context context, int type) {
            super(context);
            this.timerSync = new Object();
            this.time = 60000;
            this.codeTime = 15000;
            this.lastError = "";
            this.pattern = "*";
            this.verificationType = type;
            setOrientation(1);
            TextView textView = new TextView(context);
            this.confirmTextView = textView;
            textView.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteGrayText6));
            this.confirmTextView.setTextSize(1, 14.0f);
            this.confirmTextView.setLineSpacing(AndroidUtilities.dp(2.0f), 1.0f);
            TextView textView2 = new TextView(context);
            this.titleTextView = textView2;
            textView2.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteBlackText));
            this.titleTextView.setTextSize(1, 18.0f);
            this.titleTextView.setTypeface(AndroidUtilities.getTypeface("fonts/rmedium.ttf"));
            this.titleTextView.setGravity(LocaleController.isRTL ? 5 : 3);
            this.titleTextView.setLineSpacing(AndroidUtilities.dp(2.0f), 1.0f);
            this.titleTextView.setGravity(49);
            if (this.verificationType == 3) {
                this.confirmTextView.setGravity((LocaleController.isRTL ? 5 : 3) | 48);
                FrameLayout frameLayout = new FrameLayout(context);
                addView(frameLayout, LayoutHelper.createLinear(-2, -2, LocaleController.isRTL ? 5 : 3));
                ImageView imageView = new ImageView(context);
                imageView.setImageResource(R.drawable.phone_activate);
                if (LocaleController.isRTL) {
                    frameLayout.addView(imageView, LayoutHelper.createFrame(64.0f, 76.0f, 19, 2.0f, 2.0f, 0.0f, 0.0f));
                    frameLayout.addView(this.confirmTextView, LayoutHelper.createFrame(-1.0f, -2.0f, LocaleController.isRTL ? 5 : 3, 82.0f, 0.0f, 0.0f, 0.0f));
                } else {
                    frameLayout.addView(this.confirmTextView, LayoutHelper.createFrame(-1.0f, -2.0f, LocaleController.isRTL ? 5 : 3, 0.0f, 0.0f, 82.0f, 0.0f));
                    frameLayout.addView(imageView, LayoutHelper.createFrame(64.0f, 76.0f, 21, 0.0f, 2.0f, 0.0f, 2.0f));
                }
            } else {
                this.confirmTextView.setGravity(49);
                FrameLayout frameLayout2 = new FrameLayout(context);
                addView(frameLayout2, LayoutHelper.createLinear(-2, -2, 49));
                if (this.verificationType == 1) {
                    ImageView imageView2 = new ImageView(context);
                    this.blackImageView = imageView2;
                    imageView2.setImageResource(R.drawable.sms_devices);
                    this.blackImageView.setColorFilter(new PorterDuffColorFilter(Theme.getColor(Theme.key_windowBackgroundWhiteBlackText), PorterDuff.Mode.MULTIPLY));
                    frameLayout2.addView(this.blackImageView, LayoutHelper.createFrame(-2.0f, -2.0f, 51, 0.0f, 0.0f, 0.0f, 0.0f));
                    ImageView imageView3 = new ImageView(context);
                    this.blueImageView = imageView3;
                    imageView3.setImageResource(R.drawable.sms_bubble);
                    this.blueImageView.setColorFilter(new PorterDuffColorFilter(Theme.getColor(Theme.key_chats_actionBackground), PorterDuff.Mode.MULTIPLY));
                    frameLayout2.addView(this.blueImageView, LayoutHelper.createFrame(-2.0f, -2.0f, 51, 0.0f, 0.0f, 0.0f, 0.0f));
                    this.titleTextView.setText(LocaleController.getString("SentAppCodeTitle", R.string.SentAppCodeTitle));
                } else {
                    ImageView imageView4 = new ImageView(context);
                    this.blueImageView = imageView4;
                    imageView4.setImageResource(R.drawable.sms_code);
                    this.blueImageView.setColorFilter(new PorterDuffColorFilter(Theme.getColor(Theme.key_chats_actionBackground), PorterDuff.Mode.MULTIPLY));
                    frameLayout2.addView(this.blueImageView, LayoutHelper.createFrame(-2.0f, -2.0f, 51, 0.0f, 0.0f, 0.0f, 0.0f));
                    this.titleTextView.setText(LocaleController.getString("SentSmsCodeTitle", R.string.SentSmsCodeTitle));
                }
                addView(this.titleTextView, LayoutHelper.createLinear(-2, -2, 49, 0, 18, 0, 0));
                addView(this.confirmTextView, LayoutHelper.createLinear(-2, -2, 49, 0, 17, 0, 0));
            }
            LinearLayout linearLayout = new LinearLayout(context);
            this.codeFieldContainer = linearLayout;
            linearLayout.setOrientation(0);
            addView(this.codeFieldContainer, LayoutHelper.createLinear(-2, 36, 1));
            if (this.verificationType == 3) {
                this.codeFieldContainer.setVisibility(8);
            }
            TextView textView3 = new TextView(context) { // from class: im.uwrkaxlmjj.ui.PassportActivity.PhoneConfirmationView.1
                @Override // android.widget.TextView, android.view.View
                protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
                    super.onMeasure(widthMeasureSpec, View.MeasureSpec.makeMeasureSpec(AndroidUtilities.dp(100.0f), Integer.MIN_VALUE));
                }
            };
            this.timeText = textView3;
            textView3.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteGrayText6));
            this.timeText.setLineSpacing(AndroidUtilities.dp(2.0f), 1.0f);
            if (this.verificationType == 3) {
                this.timeText.setTextSize(1, 14.0f);
                addView(this.timeText, LayoutHelper.createLinear(-2, -2, LocaleController.isRTL ? 5 : 3));
                this.progressView = PassportActivity.this.new ProgressView(context);
                this.timeText.setGravity(LocaleController.isRTL ? 5 : 3);
                addView(this.progressView, LayoutHelper.createLinear(-1, 3, 0.0f, 12.0f, 0.0f, 0.0f));
            } else {
                this.timeText.setPadding(0, AndroidUtilities.dp(2.0f), 0, AndroidUtilities.dp(10.0f));
                this.timeText.setTextSize(1, 15.0f);
                this.timeText.setGravity(49);
                addView(this.timeText, LayoutHelper.createLinear(-2, -2, 49));
            }
            TextView textView4 = new TextView(context) { // from class: im.uwrkaxlmjj.ui.PassportActivity.PhoneConfirmationView.2
                @Override // android.widget.TextView, android.view.View
                protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
                    super.onMeasure(widthMeasureSpec, View.MeasureSpec.makeMeasureSpec(AndroidUtilities.dp(100.0f), Integer.MIN_VALUE));
                }
            };
            this.problemText = textView4;
            textView4.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteBlueText4));
            this.problemText.setLineSpacing(AndroidUtilities.dp(2.0f), 1.0f);
            this.problemText.setPadding(0, AndroidUtilities.dp(2.0f), 0, AndroidUtilities.dp(10.0f));
            this.problemText.setTextSize(1, 15.0f);
            this.problemText.setGravity(49);
            if (this.verificationType == 1) {
                this.problemText.setText(LocaleController.getString("DidNotGetTheCodeSms", R.string.DidNotGetTheCodeSms));
            } else {
                this.problemText.setText(LocaleController.getString("DidNotGetTheCode", R.string.DidNotGetTheCode));
            }
            addView(this.problemText, LayoutHelper.createLinear(-2, -2, 49));
            this.problemText.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PassportActivity$PhoneConfirmationView$BQYxcDtXFgo6jHqHgmBCJ3WKsEU
                @Override // android.view.View.OnClickListener
                public final void onClick(View view) {
                    this.f$0.lambda$new$0$PassportActivity$PhoneConfirmationView(view);
                }
            });
        }

        public /* synthetic */ void lambda$new$0$PassportActivity$PhoneConfirmationView(View v) {
            if (this.nextPressed) {
                return;
            }
            boolean email = (this.nextType == 4 && this.verificationType == 2) || this.nextType == 0;
            if (!email) {
                resendCode();
                return;
            }
            try {
                PackageInfo pInfo = ApplicationLoader.applicationContext.getPackageManager().getPackageInfo(ApplicationLoader.applicationContext.getPackageName(), 0);
                String version = String.format(Locale.US, "%s (%d)", pInfo.versionName, Integer.valueOf(pInfo.versionCode));
                Intent mailer = new Intent("android.intent.action.SEND");
                mailer.setType("message/rfc822");
                mailer.putExtra("android.intent.extra.EMAIL", new String[]{"sms@stel.com"});
                mailer.putExtra("android.intent.extra.SUBJECT", "Android registration/login issue " + version + " " + this.phone);
                mailer.putExtra("android.intent.extra.TEXT", "Phone: " + this.phone + "\nApp version: " + version + "\nOS version: SDK " + Build.VERSION.SDK_INT + "\nDevice Name: " + Build.MANUFACTURER + Build.MODEL + "\nLocale: " + Locale.getDefault() + "\nError: " + this.lastError);
                getContext().startActivity(Intent.createChooser(mailer, "Send email..."));
            } catch (Exception e) {
                AlertsCreator.showSimpleAlert(PassportActivity.this, LocaleController.getString("NoMailInstalled", R.string.NoMailInstalled));
            }
        }

        @Override // android.widget.LinearLayout, android.view.View
        protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
            ImageView imageView;
            super.onMeasure(widthMeasureSpec, heightMeasureSpec);
            if (this.verificationType != 3 && (imageView = this.blueImageView) != null) {
                int innerHeight = imageView.getMeasuredHeight() + this.titleTextView.getMeasuredHeight() + this.confirmTextView.getMeasuredHeight() + AndroidUtilities.dp(35.0f);
                int requiredHeight = AndroidUtilities.dp(80.0f);
                int maxHeight = AndroidUtilities.dp(291.0f);
                if (PassportActivity.this.scrollHeight - innerHeight >= requiredHeight) {
                    if (PassportActivity.this.scrollHeight <= maxHeight) {
                        setMeasuredDimension(getMeasuredWidth(), PassportActivity.this.scrollHeight);
                        return;
                    } else {
                        setMeasuredDimension(getMeasuredWidth(), maxHeight);
                        return;
                    }
                }
                setMeasuredDimension(getMeasuredWidth(), innerHeight + requiredHeight);
            }
        }

        @Override // android.widget.LinearLayout, android.view.ViewGroup, android.view.View
        protected void onLayout(boolean changed, int l, int t, int r, int b) {
            int t2;
            super.onLayout(changed, l, t, r, b);
            if (this.verificationType != 3 && this.blueImageView != null) {
                int bottom = this.confirmTextView.getBottom();
                int height = getMeasuredHeight() - bottom;
                if (this.problemText.getVisibility() == 0) {
                    int h = this.problemText.getMeasuredHeight();
                    t2 = (bottom + height) - h;
                    TextView textView = this.problemText;
                    textView.layout(textView.getLeft(), t2, this.problemText.getRight(), t2 + h);
                } else if (this.timeText.getVisibility() == 0) {
                    int h2 = this.timeText.getMeasuredHeight();
                    t2 = (bottom + height) - h2;
                    TextView textView2 = this.timeText;
                    textView2.layout(textView2.getLeft(), t2, this.timeText.getRight(), t2 + h2);
                } else {
                    t2 = bottom + height;
                }
                int h3 = this.codeFieldContainer.getMeasuredHeight();
                int t3 = (((t2 - bottom) - h3) / 2) + bottom;
                LinearLayout linearLayout = this.codeFieldContainer;
                linearLayout.layout(linearLayout.getLeft(), t3, this.codeFieldContainer.getRight(), t3 + h3);
            }
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void resendCode() {
            final Bundle params = new Bundle();
            params.putString("phone", this.phone);
            this.nextPressed = true;
            PassportActivity.this.needShowProgress();
            final TLRPC.TL_auth_resendCode req = new TLRPC.TL_auth_resendCode();
            req.phone_number = this.phone;
            req.phone_code_hash = this.phoneHash;
            ConnectionsManager.getInstance(PassportActivity.this.currentAccount).sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PassportActivity$PhoneConfirmationView$1Qxn3hT0o-JLDPXQ8LbXgRG-m5M
                @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                    this.f$0.lambda$resendCode$3$PassportActivity$PhoneConfirmationView(params, req, tLObject, tL_error);
                }
            }, 2);
        }

        public /* synthetic */ void lambda$resendCode$3$PassportActivity$PhoneConfirmationView(final Bundle params, final TLRPC.TL_auth_resendCode req, final TLObject response, final TLRPC.TL_error error) {
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PassportActivity$PhoneConfirmationView$c62bE1D138z2aest1UBwTmT8PeM
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$null$2$PassportActivity$PhoneConfirmationView(error, params, response, req);
                }
            });
        }

        public /* synthetic */ void lambda$null$2$PassportActivity$PhoneConfirmationView(TLRPC.TL_error error, Bundle params, TLObject response, TLRPC.TL_auth_resendCode req) {
            this.nextPressed = false;
            if (error == null) {
                PassportActivity.this.fillNextCodeParams(params, (TLRPC.TL_auth_sentCode) response, true);
            } else {
                AlertDialog dialog = (AlertDialog) AlertsCreator.processError(PassportActivity.this.currentAccount, error, PassportActivity.this, req, new Object[0]);
                if (dialog != null && error.text.contains("PHONE_CODE_EXPIRED")) {
                    dialog.setPositiveButtonListener(new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PassportActivity$PhoneConfirmationView$cvFyoFCTW13EW9cVn2ssNhAZD1o
                        @Override // android.content.DialogInterface.OnClickListener
                        public final void onClick(DialogInterface dialogInterface, int i) {
                            this.f$0.lambda$null$1$PassportActivity$PhoneConfirmationView(dialogInterface, i);
                        }
                    });
                }
            }
            PassportActivity.this.needHideProgress();
        }

        public /* synthetic */ void lambda$null$1$PassportActivity$PhoneConfirmationView(DialogInterface dialog1, int which) {
            onBackPressed(true);
            PassportActivity.this.finishFragment();
        }

        @Override // im.uwrkaxlmjj.ui.components.SlideView
        public boolean needBackButton() {
            return true;
        }

        @Override // im.uwrkaxlmjj.ui.components.SlideView
        public void onCancelPressed() {
            this.nextPressed = false;
        }

        @Override // im.uwrkaxlmjj.ui.components.SlideView
        public void setParams(Bundle params, boolean restore) {
            int i;
            int i2;
            if (params != null) {
                this.waitingForEvent = true;
                int i3 = this.verificationType;
                if (i3 == 2) {
                    AndroidUtilities.setWaitingForSms(true);
                    NotificationCenter.getGlobalInstance().addObserver(this, NotificationCenter.didReceiveSmsCode);
                } else if (i3 == 3) {
                    AndroidUtilities.setWaitingForCall(true);
                    NotificationCenter.getGlobalInstance().addObserver(this, NotificationCenter.didReceiveCall);
                }
                this.currentParams = params;
                this.phone = params.getString("phone");
                this.phoneHash = params.getString("phoneHash");
                int i4 = params.getInt("timeout");
                this.time = i4;
                this.timeout = i4;
                this.openTime = (int) (System.currentTimeMillis() / 1000);
                this.nextType = params.getInt("nextType");
                this.pattern = params.getString("pattern");
                int i5 = params.getInt("length");
                this.length = i5;
                if (i5 == 0) {
                    this.length = 5;
                }
                EditTextBoldCursor[] editTextBoldCursorArr = this.codeField;
                int i6 = 8;
                if (editTextBoldCursorArr == null || editTextBoldCursorArr.length != this.length) {
                    int a = this.length;
                    this.codeField = new EditTextBoldCursor[a];
                    int a2 = 0;
                    while (a2 < this.length) {
                        final int num = a2;
                        this.codeField[a2] = new EditTextBoldCursor(getContext());
                        this.codeField[a2].setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteBlackText));
                        this.codeField[a2].setCursorColor(Theme.getColor(Theme.key_windowBackgroundWhiteBlackText));
                        this.codeField[a2].setCursorSize(AndroidUtilities.dp(20.0f));
                        this.codeField[a2].setCursorWidth(1.5f);
                        Drawable pressedDrawable = getResources().getDrawable(R.drawable.search_dark_activated).mutate();
                        pressedDrawable.setColorFilter(new PorterDuffColorFilter(Theme.getColor(Theme.key_windowBackgroundWhiteInputFieldActivated), PorterDuff.Mode.MULTIPLY));
                        this.codeField[a2].setBackgroundDrawable(pressedDrawable);
                        this.codeField[a2].setImeOptions(268435461);
                        this.codeField[a2].setTextSize(1, 20.0f);
                        this.codeField[a2].setMaxLines(1);
                        this.codeField[a2].setTypeface(AndroidUtilities.getTypeface("fonts/rmedium.ttf"));
                        this.codeField[a2].setPadding(0, 0, 0, 0);
                        this.codeField[a2].setGravity(49);
                        if (this.verificationType == 3) {
                            this.codeField[a2].setEnabled(false);
                            this.codeField[a2].setInputType(0);
                            this.codeField[a2].setVisibility(i6);
                        } else {
                            this.codeField[a2].setInputType(3);
                        }
                        this.codeFieldContainer.addView(this.codeField[a2], LayoutHelper.createLinear(34, 36, 1, 0, 0, a2 != this.length - 1 ? 7 : 0, 0));
                        this.codeField[a2].addTextChangedListener(new TextWatcher() { // from class: im.uwrkaxlmjj.ui.PassportActivity.PhoneConfirmationView.3
                            @Override // android.text.TextWatcher
                            public void beforeTextChanged(CharSequence s, int start, int count, int after) {
                            }

                            @Override // android.text.TextWatcher
                            public void onTextChanged(CharSequence s, int start, int before, int count) {
                            }

                            @Override // android.text.TextWatcher
                            public void afterTextChanged(Editable s) {
                                int len;
                                if (!PhoneConfirmationView.this.ignoreOnTextChange && (len = s.length()) >= 1) {
                                    if (len > 1) {
                                        String text = s.toString();
                                        PhoneConfirmationView.this.ignoreOnTextChange = true;
                                        for (int a3 = 0; a3 < Math.min(PhoneConfirmationView.this.length - num, len); a3++) {
                                            if (a3 != 0) {
                                                PhoneConfirmationView.this.codeField[num + a3].setText(text.substring(a3, a3 + 1));
                                            } else {
                                                s.replace(0, len, text.substring(a3, a3 + 1));
                                            }
                                        }
                                        PhoneConfirmationView.this.ignoreOnTextChange = false;
                                    }
                                    if (num != PhoneConfirmationView.this.length - 1) {
                                        PhoneConfirmationView.this.codeField[num + 1].setSelection(PhoneConfirmationView.this.codeField[num + 1].length());
                                        PhoneConfirmationView.this.codeField[num + 1].requestFocus();
                                    }
                                    if ((num == PhoneConfirmationView.this.length - 1 || (num == PhoneConfirmationView.this.length - 2 && len >= 2)) && PhoneConfirmationView.this.getCode().length() == PhoneConfirmationView.this.length) {
                                        PhoneConfirmationView.this.onNextPressed();
                                    }
                                }
                            }
                        });
                        this.codeField[a2].setOnKeyListener(new View.OnKeyListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PassportActivity$PhoneConfirmationView$UdNUtduOu4Vu9D22r1fY8lau_gQ
                            @Override // android.view.View.OnKeyListener
                            public final boolean onKey(View view, int i7, KeyEvent keyEvent) {
                                return this.f$0.lambda$setParams$4$PassportActivity$PhoneConfirmationView(num, view, i7, keyEvent);
                            }
                        });
                        this.codeField[a2].setOnEditorActionListener(new TextView.OnEditorActionListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PassportActivity$PhoneConfirmationView$nRYFdhe40sXQ4C0695mg4rF6ULw
                            @Override // android.widget.TextView.OnEditorActionListener
                            public final boolean onEditorAction(TextView textView, int i7, KeyEvent keyEvent) {
                                return this.f$0.lambda$setParams$5$PassportActivity$PhoneConfirmationView(textView, i7, keyEvent);
                            }
                        });
                        a2++;
                        i6 = 8;
                    }
                } else {
                    int a3 = 0;
                    while (true) {
                        EditTextBoldCursor[] editTextBoldCursorArr2 = this.codeField;
                        if (a3 >= editTextBoldCursorArr2.length) {
                            break;
                        }
                        editTextBoldCursorArr2[a3].setText("");
                        a3++;
                    }
                }
                ProgressView progressView = this.progressView;
                if (progressView != null) {
                    progressView.setVisibility(this.nextType != 0 ? 0 : 8);
                }
                if (this.phone == null) {
                    return;
                }
                String number = PhoneFormat.getInstance().format(Marker.ANY_NON_NULL_MARKER + this.phone);
                CharSequence str = "";
                int i7 = this.verificationType;
                if (i7 == 2) {
                    str = AndroidUtilities.replaceTags(LocaleController.formatString("SentSmsCode", R.string.SentSmsCode, LocaleController.addNbsp(number)));
                } else if (i7 == 3) {
                    str = AndroidUtilities.replaceTags(LocaleController.formatString("SentCallCode", R.string.SentCallCode, LocaleController.addNbsp(number)));
                } else if (i7 == 4) {
                    str = AndroidUtilities.replaceTags(LocaleController.formatString("SentCallOnly", R.string.SentCallOnly, LocaleController.addNbsp(number)));
                }
                this.confirmTextView.setText(str);
                if (this.verificationType != 3) {
                    AndroidUtilities.showKeyboard(this.codeField[0]);
                    this.codeField[0].requestFocus();
                } else {
                    AndroidUtilities.hideKeyboard(this.codeField[0]);
                }
                destroyTimer();
                destroyCodeTimer();
                this.lastCurrentTime = System.currentTimeMillis();
                if (this.verificationType == 3 && ((i2 = this.nextType) == 4 || i2 == 2)) {
                    this.problemText.setVisibility(8);
                    this.timeText.setVisibility(0);
                    int i8 = this.nextType;
                    if (i8 == 4) {
                        this.timeText.setText(LocaleController.formatString("CallText", R.string.CallText, 1, 0));
                    } else if (i8 == 2) {
                        this.timeText.setText(LocaleController.formatString("SmsText", R.string.SmsText, 1, 0));
                    }
                    createTimer();
                    return;
                }
                if (this.verificationType == 2 && ((i = this.nextType) == 4 || i == 3)) {
                    this.timeText.setText(LocaleController.formatString("CallText", R.string.CallText, 2, 0));
                    this.problemText.setVisibility(this.time < 1000 ? 0 : 8);
                    this.timeText.setVisibility(this.time < 1000 ? 8 : 0);
                    createTimer();
                    return;
                }
                if (this.verificationType == 4 && this.nextType == 2) {
                    this.timeText.setText(LocaleController.formatString("SmsText", R.string.SmsText, 2, 0));
                    this.problemText.setVisibility(this.time < 1000 ? 0 : 8);
                    this.timeText.setVisibility(this.time < 1000 ? 8 : 0);
                    createTimer();
                    return;
                }
                this.timeText.setVisibility(8);
                this.problemText.setVisibility(8);
                createCodeTimer();
            }
        }

        public /* synthetic */ boolean lambda$setParams$4$PassportActivity$PhoneConfirmationView(int num, View v, int keyCode, KeyEvent event) {
            if (keyCode == 67 && this.codeField[num].length() == 0 && num > 0) {
                EditTextBoldCursor[] editTextBoldCursorArr = this.codeField;
                editTextBoldCursorArr[num - 1].setSelection(editTextBoldCursorArr[num - 1].length());
                this.codeField[num - 1].requestFocus();
                this.codeField[num - 1].dispatchKeyEvent(event);
                return true;
            }
            return false;
        }

        public /* synthetic */ boolean lambda$setParams$5$PassportActivity$PhoneConfirmationView(TextView textView, int i, KeyEvent keyEvent) {
            if (i == 5) {
                onNextPressed();
                return true;
            }
            return false;
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void createCodeTimer() {
            if (this.codeTimer != null) {
                return;
            }
            this.codeTime = 15000;
            this.codeTimer = new Timer();
            this.lastCodeTime = System.currentTimeMillis();
            this.codeTimer.schedule(new AnonymousClass4(), 0L, 1000L);
        }

        /* JADX INFO: renamed from: im.uwrkaxlmjj.ui.PassportActivity$PhoneConfirmationView$4, reason: invalid class name */
        class AnonymousClass4 extends TimerTask {
            AnonymousClass4() {
            }

            @Override // java.util.TimerTask, java.lang.Runnable
            public void run() {
                AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PassportActivity$PhoneConfirmationView$4$erBikJPBf4rK4nZW01HfUc5g7b0
                    @Override // java.lang.Runnable
                    public final void run() {
                        this.f$0.lambda$run$0$PassportActivity$PhoneConfirmationView$4();
                    }
                });
            }

            public /* synthetic */ void lambda$run$0$PassportActivity$PhoneConfirmationView$4() {
                double currentTime = System.currentTimeMillis();
                double diff = currentTime - PhoneConfirmationView.this.lastCodeTime;
                PhoneConfirmationView.this.lastCodeTime = currentTime;
                PhoneConfirmationView phoneConfirmationView = PhoneConfirmationView.this;
                phoneConfirmationView.codeTime = (int) (((double) phoneConfirmationView.codeTime) - diff);
                if (PhoneConfirmationView.this.codeTime <= 1000) {
                    PhoneConfirmationView.this.problemText.setVisibility(0);
                    PhoneConfirmationView.this.timeText.setVisibility(8);
                    PhoneConfirmationView.this.destroyCodeTimer();
                }
            }
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void destroyCodeTimer() {
            try {
                synchronized (this.timerSync) {
                    if (this.codeTimer != null) {
                        this.codeTimer.cancel();
                        this.codeTimer = null;
                    }
                }
            } catch (Exception e) {
                FileLog.e(e);
            }
        }

        private void createTimer() {
            if (this.timeTimer != null) {
                return;
            }
            Timer timer = new Timer();
            this.timeTimer = timer;
            timer.schedule(new TimerTask() { // from class: im.uwrkaxlmjj.ui.PassportActivity.PhoneConfirmationView.5
                @Override // java.util.TimerTask, java.lang.Runnable
                public void run() {
                    if (PhoneConfirmationView.this.timeTimer == null) {
                        return;
                    }
                    double currentTime = System.currentTimeMillis();
                    double diff = currentTime - PhoneConfirmationView.this.lastCurrentTime;
                    PhoneConfirmationView phoneConfirmationView = PhoneConfirmationView.this;
                    phoneConfirmationView.time = (int) (((double) phoneConfirmationView.time) - diff);
                    PhoneConfirmationView.this.lastCurrentTime = currentTime;
                    AndroidUtilities.runOnUIThread(new AnonymousClass1());
                }

                /* JADX INFO: renamed from: im.uwrkaxlmjj.ui.PassportActivity$PhoneConfirmationView$5$1, reason: invalid class name */
                class AnonymousClass1 implements Runnable {
                    AnonymousClass1() {
                    }

                    @Override // java.lang.Runnable
                    public void run() {
                        if (PhoneConfirmationView.this.time >= 1000) {
                            int minutes = (PhoneConfirmationView.this.time / 1000) / 60;
                            int seconds = (PhoneConfirmationView.this.time / 1000) - (minutes * 60);
                            if (PhoneConfirmationView.this.nextType == 4 || PhoneConfirmationView.this.nextType == 3) {
                                PhoneConfirmationView.this.timeText.setText(LocaleController.formatString("CallText", R.string.CallText, Integer.valueOf(minutes), Integer.valueOf(seconds)));
                            } else if (PhoneConfirmationView.this.nextType == 2) {
                                PhoneConfirmationView.this.timeText.setText(LocaleController.formatString("SmsText", R.string.SmsText, Integer.valueOf(minutes), Integer.valueOf(seconds)));
                            }
                            if (PhoneConfirmationView.this.progressView != null) {
                                PhoneConfirmationView.this.progressView.setProgress(1.0f - (PhoneConfirmationView.this.time / PhoneConfirmationView.this.timeout));
                                return;
                            }
                            return;
                        }
                        if (PhoneConfirmationView.this.progressView != null) {
                            PhoneConfirmationView.this.progressView.setProgress(1.0f);
                        }
                        PhoneConfirmationView.this.destroyTimer();
                        if (PhoneConfirmationView.this.verificationType != 3) {
                            if (PhoneConfirmationView.this.verificationType == 2 || PhoneConfirmationView.this.verificationType == 4) {
                                if (PhoneConfirmationView.this.nextType == 4 || PhoneConfirmationView.this.nextType == 2) {
                                    if (PhoneConfirmationView.this.nextType == 4) {
                                        PhoneConfirmationView.this.timeText.setText(LocaleController.getString("Calling", R.string.Calling));
                                    } else {
                                        PhoneConfirmationView.this.timeText.setText(LocaleController.getString("SendingSms", R.string.SendingSms));
                                    }
                                    PhoneConfirmationView.this.createCodeTimer();
                                    TLRPC.TL_auth_resendCode req = new TLRPC.TL_auth_resendCode();
                                    req.phone_number = PhoneConfirmationView.this.phone;
                                    req.phone_code_hash = PhoneConfirmationView.this.phoneHash;
                                    ConnectionsManager.getInstance(PassportActivity.this.currentAccount).sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PassportActivity$PhoneConfirmationView$5$1$-7r6qBRPjJI96ITpIhhOfVFIkgs
                                        @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                                        public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                                            this.f$0.lambda$run$1$PassportActivity$PhoneConfirmationView$5$1(tLObject, tL_error);
                                        }
                                    }, 2);
                                    return;
                                }
                                if (PhoneConfirmationView.this.nextType == 3) {
                                    AndroidUtilities.setWaitingForSms(false);
                                    NotificationCenter.getGlobalInstance().removeObserver(this, NotificationCenter.didReceiveSmsCode);
                                    PhoneConfirmationView.this.waitingForEvent = false;
                                    PhoneConfirmationView.this.destroyCodeTimer();
                                    PhoneConfirmationView.this.resendCode();
                                    return;
                                }
                                return;
                            }
                            return;
                        }
                        AndroidUtilities.setWaitingForCall(false);
                        NotificationCenter.getGlobalInstance().removeObserver(this, NotificationCenter.didReceiveCall);
                        PhoneConfirmationView.this.waitingForEvent = false;
                        PhoneConfirmationView.this.destroyCodeTimer();
                        PhoneConfirmationView.this.resendCode();
                    }

                    public /* synthetic */ void lambda$run$1$PassportActivity$PhoneConfirmationView$5$1(TLObject response, final TLRPC.TL_error error) {
                        if (error != null && error.text != null) {
                            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PassportActivity$PhoneConfirmationView$5$1$NPY-548LlQyHp_H7wvkttfQKe7Y
                                @Override // java.lang.Runnable
                                public final void run() {
                                    this.f$0.lambda$null$0$PassportActivity$PhoneConfirmationView$5$1(error);
                                }
                            });
                        }
                    }

                    public /* synthetic */ void lambda$null$0$PassportActivity$PhoneConfirmationView$5$1(TLRPC.TL_error error) {
                        PhoneConfirmationView.this.lastError = error.text;
                    }
                }
            }, 0L, 1000L);
        }

        /* JADX INFO: Access modifiers changed from: private */
        public void destroyTimer() {
            try {
                synchronized (this.timerSync) {
                    if (this.timeTimer != null) {
                        this.timeTimer.cancel();
                        this.timeTimer = null;
                    }
                }
            } catch (Exception e) {
                FileLog.e(e);
            }
        }

        /* JADX INFO: Access modifiers changed from: private */
        public String getCode() {
            if (this.codeField == null) {
                return "";
            }
            StringBuilder codeBuilder = new StringBuilder();
            int a = 0;
            while (true) {
                EditTextBoldCursor[] editTextBoldCursorArr = this.codeField;
                if (a < editTextBoldCursorArr.length) {
                    codeBuilder.append(PhoneFormat.stripExceptNumbers(editTextBoldCursorArr[a].getText().toString()));
                    a++;
                } else {
                    return codeBuilder.toString();
                }
            }
        }

        @Override // im.uwrkaxlmjj.ui.components.SlideView
        public void onNextPressed() {
            if (this.nextPressed) {
                return;
            }
            String code = getCode();
            if (TextUtils.isEmpty(code)) {
                AndroidUtilities.shakeView(this.codeFieldContainer, 2.0f, 0);
                return;
            }
            this.nextPressed = true;
            int i = this.verificationType;
            if (i == 2) {
                AndroidUtilities.setWaitingForSms(false);
                NotificationCenter.getGlobalInstance().removeObserver(this, NotificationCenter.didReceiveSmsCode);
            } else if (i == 3) {
                AndroidUtilities.setWaitingForCall(false);
                NotificationCenter.getGlobalInstance().removeObserver(this, NotificationCenter.didReceiveCall);
            }
            this.waitingForEvent = false;
            PassportActivity.this.showEditDoneProgress(true, true);
            final TLRPC.TL_account_verifyPhone req = new TLRPC.TL_account_verifyPhone();
            req.phone_number = this.phone;
            req.phone_code = code;
            req.phone_code_hash = this.phoneHash;
            destroyTimer();
            PassportActivity.this.needShowProgress();
            ConnectionsManager.getInstance(PassportActivity.this.currentAccount).sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PassportActivity$PhoneConfirmationView$QpT_P78Y60IJ7U8SRT2gUny2I6Y
                @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                    this.f$0.lambda$onNextPressed$7$PassportActivity$PhoneConfirmationView(req, tLObject, tL_error);
                }
            }, 2);
        }

        public /* synthetic */ void lambda$onNextPressed$7$PassportActivity$PhoneConfirmationView(final TLRPC.TL_account_verifyPhone req, TLObject response, final TLRPC.TL_error error) {
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PassportActivity$PhoneConfirmationView$36o6OJOsS81Mbfg2MuPqxFQ3Plg
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$null$6$PassportActivity$PhoneConfirmationView(error, req);
                }
            });
        }

        public /* synthetic */ void lambda$null$6$PassportActivity$PhoneConfirmationView(TLRPC.TL_error error, TLRPC.TL_account_verifyPhone req) {
            int i;
            int i2;
            PassportActivity.this.needHideProgress();
            this.nextPressed = false;
            if (error != null) {
                this.lastError = error.text;
                if ((this.verificationType == 3 && ((i2 = this.nextType) == 4 || i2 == 2)) || ((this.verificationType == 2 && ((i = this.nextType) == 4 || i == 3)) || (this.verificationType == 4 && this.nextType == 2))) {
                    createTimer();
                }
                int i3 = this.verificationType;
                if (i3 == 2) {
                    AndroidUtilities.setWaitingForSms(true);
                    NotificationCenter.getGlobalInstance().addObserver(this, NotificationCenter.didReceiveSmsCode);
                } else if (i3 == 3) {
                    AndroidUtilities.setWaitingForCall(true);
                    NotificationCenter.getGlobalInstance().addObserver(this, NotificationCenter.didReceiveCall);
                }
                this.waitingForEvent = true;
                if (this.verificationType != 3) {
                    AlertsCreator.processError(PassportActivity.this.currentAccount, error, PassportActivity.this, req, new Object[0]);
                }
                PassportActivity.this.showEditDoneProgress(true, false);
                if (error.text.contains("PHONE_CODE_EMPTY") || error.text.contains("PHONE_CODE_INVALID")) {
                    int a = 0;
                    while (true) {
                        EditTextBoldCursor[] editTextBoldCursorArr = this.codeField;
                        if (a < editTextBoldCursorArr.length) {
                            editTextBoldCursorArr[a].setText("");
                            a++;
                        } else {
                            editTextBoldCursorArr[0].requestFocus();
                            return;
                        }
                    }
                } else if (error.text.contains("PHONE_CODE_EXPIRED")) {
                    onBackPressed(true);
                    PassportActivity.this.setPage(0, true, null);
                }
            } else {
                destroyTimer();
                destroyCodeTimer();
                PassportActivityDelegate passportActivityDelegate = PassportActivity.this.delegate;
                TLRPC.TL_secureRequiredType tL_secureRequiredType = PassportActivity.this.currentType;
                String str = (String) PassportActivity.this.currentValues.get("phone");
                final PassportActivity passportActivity = PassportActivity.this;
                passportActivityDelegate.saveValue(tL_secureRequiredType, str, null, null, null, null, null, null, null, null, new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$xzENbkKpF-qM3VMQf1lGztHfHq0
                    @Override // java.lang.Runnable
                    public final void run() {
                        passportActivity.finishFragment();
                    }
                }, null);
            }
        }

        @Override // im.uwrkaxlmjj.ui.components.SlideView
        public boolean onBackPressed(boolean force) {
            if (!force) {
                AlertDialog.Builder builder = new AlertDialog.Builder(PassportActivity.this.getParentActivity());
                builder.setTitle(LocaleController.getString("AppName", R.string.AppName));
                builder.setMessage(LocaleController.getString("StopVerification", R.string.StopVerification));
                builder.setPositiveButton(LocaleController.getString("Continue", R.string.Continue), null);
                builder.setNegativeButton(LocaleController.getString("Stop", R.string.Stop), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PassportActivity$PhoneConfirmationView$1Ap7MGb0TfqdBpTDsmrFdGA_Pjo
                    @Override // android.content.DialogInterface.OnClickListener
                    public final void onClick(DialogInterface dialogInterface, int i) {
                        this.f$0.lambda$onBackPressed$8$PassportActivity$PhoneConfirmationView(dialogInterface, i);
                    }
                });
                PassportActivity.this.showDialog(builder.create());
                return false;
            }
            TLRPC.TL_auth_cancelCode req = new TLRPC.TL_auth_cancelCode();
            req.phone_number = this.phone;
            req.phone_code_hash = this.phoneHash;
            ConnectionsManager.getInstance(PassportActivity.this.currentAccount).sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$PassportActivity$PhoneConfirmationView$5Mycl6ECjtYzo9aQxSdDzzZnDzw
                @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                    PassportActivity.PhoneConfirmationView.lambda$onBackPressed$9(tLObject, tL_error);
                }
            }, 2);
            destroyTimer();
            destroyCodeTimer();
            this.currentParams = null;
            int i = this.verificationType;
            if (i == 2) {
                AndroidUtilities.setWaitingForSms(false);
                NotificationCenter.getGlobalInstance().removeObserver(this, NotificationCenter.didReceiveSmsCode);
            } else if (i == 3) {
                AndroidUtilities.setWaitingForCall(false);
                NotificationCenter.getGlobalInstance().removeObserver(this, NotificationCenter.didReceiveCall);
            }
            this.waitingForEvent = false;
            return true;
        }

        public /* synthetic */ void lambda$onBackPressed$8$PassportActivity$PhoneConfirmationView(DialogInterface dialogInterface, int i) {
            onBackPressed(true);
            PassportActivity.this.setPage(0, true, null);
        }

        static /* synthetic */ void lambda$onBackPressed$9(TLObject response, TLRPC.TL_error error) {
        }

        @Override // im.uwrkaxlmjj.ui.components.SlideView
        public void onDestroyActivity() {
            super.onDestroyActivity();
            int i = this.verificationType;
            if (i == 2) {
                AndroidUtilities.setWaitingForSms(false);
                NotificationCenter.getGlobalInstance().removeObserver(this, NotificationCenter.didReceiveSmsCode);
            } else if (i == 3) {
                AndroidUtilities.setWaitingForCall(false);
                NotificationCenter.getGlobalInstance().removeObserver(this, NotificationCenter.didReceiveCall);
            }
            this.waitingForEvent = false;
            destroyTimer();
            destroyCodeTimer();
        }

        @Override // im.uwrkaxlmjj.ui.components.SlideView
        public void onShow() {
            super.onShow();
            LinearLayout linearLayout = this.codeFieldContainer;
            if (linearLayout != null && linearLayout.getVisibility() == 0) {
                for (int a = this.codeField.length - 1; a >= 0; a--) {
                    if (a == 0 || this.codeField[a].length() != 0) {
                        this.codeField[a].requestFocus();
                        EditTextBoldCursor[] editTextBoldCursorArr = this.codeField;
                        editTextBoldCursorArr[a].setSelection(editTextBoldCursorArr[a].length());
                        AndroidUtilities.showKeyboard(this.codeField[a]);
                        return;
                    }
                }
            }
        }

        @Override // im.uwrkaxlmjj.messenger.NotificationCenter.NotificationCenterDelegate
        public void didReceivedNotification(int id, int account, Object... args) {
            if (!this.waitingForEvent || this.codeField == null) {
                return;
            }
            if (id == NotificationCenter.didReceiveSmsCode) {
                this.codeField[0].setText("" + args[0]);
                onNextPressed();
                return;
            }
            if (id == NotificationCenter.didReceiveCall) {
                String num = "" + args[0];
                if (!AndroidUtilities.checkPhonePattern(this.pattern, num)) {
                    return;
                }
                this.ignoreOnTextChange = true;
                this.codeField[0].setText(num);
                this.ignoreOnTextChange = false;
                onNextPressed();
            }
        }
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public ThemeDescription[] getThemeDescriptions() {
        ArrayList<ThemeDescription> arrayList = new ArrayList<>();
        arrayList.add(new ThemeDescription(this.fragmentView, ThemeDescription.FLAG_BACKGROUND, null, null, null, null, Theme.key_windowBackgroundGray));
        arrayList.add(new ThemeDescription(this.actionBar, ThemeDescription.FLAG_BACKGROUND, null, null, null, null, Theme.key_actionBarDefault));
        arrayList.add(new ThemeDescription(this.scrollView, ThemeDescription.FLAG_LISTGLOWCOLOR, null, null, null, null, Theme.key_actionBarDefault));
        arrayList.add(new ThemeDescription(this.actionBar, ThemeDescription.FLAG_AB_ITEMSCOLOR, null, null, null, null, Theme.key_actionBarDefaultIcon));
        arrayList.add(new ThemeDescription(this.actionBar, ThemeDescription.FLAG_AB_TITLECOLOR, null, null, null, null, Theme.key_actionBarDefaultTitle));
        arrayList.add(new ThemeDescription(this.actionBar, ThemeDescription.FLAG_AB_SELECTORCOLOR, null, null, null, null, Theme.key_actionBarDefaultSelector));
        arrayList.add(new ThemeDescription(this.actionBar, ThemeDescription.FLAG_AB_SEARCH, null, null, null, null, Theme.key_actionBarDefaultSearch));
        arrayList.add(new ThemeDescription(this.actionBar, ThemeDescription.FLAG_AB_SEARCHPLACEHOLDER, null, null, null, null, Theme.key_actionBarDefaultSearchPlaceholder));
        arrayList.add(new ThemeDescription(this.linearLayout2, 0, new Class[]{View.class}, Theme.dividerPaint, null, null, Theme.key_divider));
        arrayList.add(new ThemeDescription(this.extraBackgroundView, ThemeDescription.FLAG_BACKGROUND, null, null, null, null, Theme.key_windowBackgroundWhite));
        View view = this.extraBackgroundView2;
        if (view != null) {
            arrayList.add(new ThemeDescription(view, ThemeDescription.FLAG_BACKGROUND, null, null, null, null, Theme.key_windowBackgroundWhite));
        }
        for (int a = 0; a < this.dividers.size(); a++) {
            arrayList.add(new ThemeDescription(this.dividers.get(a), ThemeDescription.FLAG_BACKGROUND, null, null, null, null, Theme.key_divider));
        }
        for (Map.Entry<SecureDocument, SecureDocumentCell> entry : this.documentsCells.entrySet()) {
            SecureDocumentCell cell = entry.getValue();
            arrayList.add(new ThemeDescription(cell, ThemeDescription.FLAG_SELECTORWHITE, new Class[]{SecureDocumentCell.class}, null, null, null, Theme.key_windowBackgroundWhite));
            arrayList.add(new ThemeDescription(cell, 0, new Class[]{SecureDocumentCell.class}, new String[]{"textView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteBlackText));
            arrayList.add(new ThemeDescription(cell, 0, new Class[]{SecureDocumentCell.class}, new String[]{"valueTextView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteGrayText2));
        }
        arrayList.add(new ThemeDescription(this.linearLayout2, ThemeDescription.FLAG_SELECTORWHITE, new Class[]{TextDetailSettingsCell.class}, null, null, null, Theme.key_windowBackgroundWhite));
        arrayList.add(new ThemeDescription(this.linearLayout2, 0, new Class[]{TextDetailSettingsCell.class}, new String[]{"textView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteBlackText));
        arrayList.add(new ThemeDescription(this.linearLayout2, 0, new Class[]{TextDetailSettingsCell.class}, new String[]{"valueTextView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteGrayText2));
        arrayList.add(new ThemeDescription(this.linearLayout2, ThemeDescription.FLAG_SELECTORWHITE, new Class[]{TextSettingsCell.class}, null, null, null, Theme.key_windowBackgroundWhite));
        arrayList.add(new ThemeDescription(this.linearLayout2, 0, new Class[]{TextSettingsCell.class}, new String[]{"textView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteBlackText));
        arrayList.add(new ThemeDescription(this.linearLayout2, 0, new Class[]{TextSettingsCell.class}, new String[]{"valueTextView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteValueText));
        arrayList.add(new ThemeDescription(this.linearLayout2, ThemeDescription.FLAG_BACKGROUNDFILTER, new Class[]{ShadowSectionCell.class}, null, null, null, Theme.key_windowBackgroundGrayShadow));
        arrayList.add(new ThemeDescription(this.linearLayout2, ThemeDescription.FLAG_SELECTORWHITE, new Class[]{TextDetailSecureCell.class}, null, null, null, Theme.key_windowBackgroundWhite));
        arrayList.add(new ThemeDescription(this.linearLayout2, ThemeDescription.FLAG_TEXTCOLOR, new Class[]{TextDetailSecureCell.class}, new String[]{"textView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteBlackText));
        arrayList.add(new ThemeDescription(this.linearLayout2, ThemeDescription.FLAG_TEXTCOLOR, new Class[]{TextDetailSecureCell.class}, null, null, null, Theme.key_divider));
        arrayList.add(new ThemeDescription(this.linearLayout2, ThemeDescription.FLAG_TEXTCOLOR, new Class[]{TextDetailSecureCell.class}, new String[]{"valueTextView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteGrayText2));
        arrayList.add(new ThemeDescription(this.linearLayout2, ThemeDescription.FLAG_IMAGECOLOR, new Class[]{TextDetailSecureCell.class}, new String[]{"checkImageView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_featuredStickers_addedIcon));
        arrayList.add(new ThemeDescription(this.linearLayout2, ThemeDescription.FLAG_CELLBACKGROUNDCOLOR, new Class[]{HeaderCell.class}, null, null, null, Theme.key_windowBackgroundWhite));
        arrayList.add(new ThemeDescription(this.linearLayout2, 0, new Class[]{HeaderCell.class}, new String[]{"textView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteBlueHeader));
        arrayList.add(new ThemeDescription(this.linearLayout2, ThemeDescription.FLAG_BACKGROUNDFILTER, new Class[]{TextInfoPrivacyCell.class}, null, null, null, Theme.key_windowBackgroundGrayShadow));
        arrayList.add(new ThemeDescription(this.linearLayout2, 0, new Class[]{TextInfoPrivacyCell.class}, new String[]{"textView"}, (Paint[]) null, (Drawable[]) null, (ThemeDescription.ThemeDescriptionDelegate) null, Theme.key_windowBackgroundWhiteGrayText4));
        if (this.inputFields != null) {
            int a2 = 0;
            while (true) {
                EditTextBoldCursor[] editTextBoldCursorArr = this.inputFields;
                if (a2 >= editTextBoldCursorArr.length) {
                    break;
                }
                arrayList.add(new ThemeDescription((View) editTextBoldCursorArr[a2].getParent(), ThemeDescription.FLAG_BACKGROUND, null, null, null, null, Theme.key_windowBackgroundWhite));
                arrayList.add(new ThemeDescription(this.inputFields[a2], ThemeDescription.FLAG_TEXTCOLOR | ThemeDescription.FLAG_CURSORCOLOR, null, null, null, null, Theme.key_windowBackgroundWhiteBlackText));
                arrayList.add(new ThemeDescription(this.inputFields[a2], ThemeDescription.FLAG_HINTTEXTCOLOR, null, null, null, null, Theme.key_windowBackgroundWhiteHintText));
                arrayList.add(new ThemeDescription(this.inputFields[a2], ThemeDescription.FLAG_HINTTEXTCOLOR | ThemeDescription.FLAG_PROGRESSBAR, null, null, null, null, Theme.key_windowBackgroundWhiteBlueHeader));
                arrayList.add(new ThemeDescription(this.inputFields[a2], ThemeDescription.FLAG_BACKGROUNDFILTER, null, null, null, null, Theme.key_windowBackgroundWhiteInputField));
                arrayList.add(new ThemeDescription(this.inputFields[a2], ThemeDescription.FLAG_BACKGROUNDFILTER | ThemeDescription.FLAG_DRAWABLESELECTEDSTATE, null, null, null, null, Theme.key_windowBackgroundWhiteInputFieldActivated));
                arrayList.add(new ThemeDescription(this.inputFields[a2], ThemeDescription.FLAG_PROGRESSBAR | ThemeDescription.FLAG_BACKGROUNDFILTER, null, null, null, null, Theme.key_windowBackgroundWhiteRedText3));
                a2++;
            }
        } else {
            arrayList.add(new ThemeDescription(null, ThemeDescription.FLAG_TEXTCOLOR, null, null, null, null, Theme.key_windowBackgroundWhiteBlackText));
            arrayList.add(new ThemeDescription(null, ThemeDescription.FLAG_HINTTEXTCOLOR, null, null, null, null, Theme.key_windowBackgroundWhiteHintText));
            arrayList.add(new ThemeDescription(null, ThemeDescription.FLAG_PROGRESSBAR | ThemeDescription.FLAG_HINTTEXTCOLOR, null, null, null, null, Theme.key_windowBackgroundWhiteBlueHeader));
            arrayList.add(new ThemeDescription(null, ThemeDescription.FLAG_BACKGROUNDFILTER, null, null, null, null, Theme.key_windowBackgroundWhiteInputField));
            arrayList.add(new ThemeDescription(null, ThemeDescription.FLAG_DRAWABLESELECTEDSTATE | ThemeDescription.FLAG_BACKGROUNDFILTER, null, null, null, null, Theme.key_windowBackgroundWhiteInputFieldActivated));
            arrayList.add(new ThemeDescription(null, ThemeDescription.FLAG_BACKGROUNDFILTER | ThemeDescription.FLAG_PROGRESSBAR, null, null, null, null, Theme.key_windowBackgroundWhiteRedText3));
        }
        if (this.inputExtraFields != null) {
            int a3 = 0;
            while (true) {
                EditTextBoldCursor[] editTextBoldCursorArr2 = this.inputExtraFields;
                if (a3 >= editTextBoldCursorArr2.length) {
                    break;
                }
                arrayList.add(new ThemeDescription((View) editTextBoldCursorArr2[a3].getParent(), ThemeDescription.FLAG_BACKGROUND, null, null, null, null, Theme.key_windowBackgroundWhite));
                arrayList.add(new ThemeDescription(this.inputExtraFields[a3], ThemeDescription.FLAG_TEXTCOLOR | ThemeDescription.FLAG_CURSORCOLOR, null, null, null, null, Theme.key_windowBackgroundWhiteBlackText));
                arrayList.add(new ThemeDescription(this.inputExtraFields[a3], ThemeDescription.FLAG_HINTTEXTCOLOR, null, null, null, null, Theme.key_windowBackgroundWhiteHintText));
                arrayList.add(new ThemeDescription(this.inputExtraFields[a3], ThemeDescription.FLAG_HINTTEXTCOLOR | ThemeDescription.FLAG_PROGRESSBAR, null, null, null, null, Theme.key_windowBackgroundWhiteBlueHeader));
                arrayList.add(new ThemeDescription(this.inputExtraFields[a3], ThemeDescription.FLAG_BACKGROUNDFILTER, null, null, null, null, Theme.key_windowBackgroundWhiteInputField));
                arrayList.add(new ThemeDescription(this.inputExtraFields[a3], ThemeDescription.FLAG_BACKGROUNDFILTER | ThemeDescription.FLAG_DRAWABLESELECTEDSTATE, null, null, null, null, Theme.key_windowBackgroundWhiteInputFieldActivated));
                arrayList.add(new ThemeDescription(this.inputExtraFields[a3], ThemeDescription.FLAG_PROGRESSBAR | ThemeDescription.FLAG_BACKGROUNDFILTER, null, null, null, null, Theme.key_windowBackgroundWhiteRedText3));
                a3++;
            }
        }
        arrayList.add(new ThemeDescription(this.emptyView, ThemeDescription.FLAG_PROGRESSBAR, null, null, null, null, Theme.key_progressCircle));
        arrayList.add(new ThemeDescription(this.noPasswordImageView, ThemeDescription.FLAG_IMAGECOLOR, null, null, null, null, Theme.key_chat_messagePanelIcons));
        arrayList.add(new ThemeDescription(this.noPasswordTextView, ThemeDescription.FLAG_TEXTCOLOR, null, null, null, null, Theme.key_windowBackgroundWhiteGrayText4));
        arrayList.add(new ThemeDescription(this.noPasswordSetTextView, ThemeDescription.FLAG_TEXTCOLOR, null, null, null, null, Theme.key_windowBackgroundWhiteBlueText5));
        arrayList.add(new ThemeDescription(this.passwordForgotButton, ThemeDescription.FLAG_TEXTCOLOR, null, null, null, null, Theme.key_windowBackgroundWhiteBlueText4));
        arrayList.add(new ThemeDescription(this.plusTextView, ThemeDescription.FLAG_TEXTCOLOR, null, null, null, null, Theme.key_windowBackgroundWhiteBlackText));
        arrayList.add(new ThemeDescription(this.acceptTextView, ThemeDescription.FLAG_TEXTCOLOR, null, null, null, null, Theme.key_passport_authorizeText));
        arrayList.add(new ThemeDescription(this.bottomLayout, ThemeDescription.FLAG_BACKGROUNDFILTER, null, null, null, null, Theme.key_passport_authorizeBackground));
        arrayList.add(new ThemeDescription(this.bottomLayout, ThemeDescription.FLAG_DRAWABLESELECTEDSTATE | ThemeDescription.FLAG_BACKGROUNDFILTER, null, null, null, null, Theme.key_passport_authorizeBackgroundSelected));
        arrayList.add(new ThemeDescription(this.progressView, 0, null, null, null, null, Theme.key_contextProgressInner2));
        arrayList.add(new ThemeDescription(this.progressView, 0, null, null, null, null, Theme.key_contextProgressOuter2));
        arrayList.add(new ThemeDescription(this.progressViewButton, 0, null, null, null, null, Theme.key_contextProgressInner2));
        arrayList.add(new ThemeDescription(this.progressViewButton, 0, null, null, null, null, Theme.key_contextProgressOuter2));
        arrayList.add(new ThemeDescription(this.emptyImageView, ThemeDescription.FLAG_IMAGECOLOR, null, null, null, null, Theme.key_sessions_devicesImage));
        arrayList.add(new ThemeDescription(this.emptyTextView1, ThemeDescription.FLAG_TEXTCOLOR, null, null, null, null, Theme.key_windowBackgroundWhiteGrayText2));
        arrayList.add(new ThemeDescription(this.emptyTextView2, ThemeDescription.FLAG_TEXTCOLOR, null, null, null, null, Theme.key_windowBackgroundWhiteGrayText2));
        arrayList.add(new ThemeDescription(this.emptyTextView3, ThemeDescription.FLAG_TEXTCOLOR, null, null, null, null, Theme.key_windowBackgroundWhiteBlueText4));
        return (ThemeDescription[]) arrayList.toArray(new ThemeDescription[0]);
    }
}
