package im.uwrkaxlmjj.ui.components;

import android.animation.Animator;
import android.animation.AnimatorListenerAdapter;
import android.animation.AnimatorSet;
import android.animation.ObjectAnimator;
import android.animation.ValueAnimator;
import android.app.Activity;
import android.content.ClipDescription;
import android.content.Context;
import android.content.DialogInterface;
import android.content.SharedPreferences;
import android.content.res.ColorStateList;
import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.ColorFilter;
import android.graphics.Paint;
import android.graphics.PorterDuff;
import android.graphics.PorterDuffColorFilter;
import android.graphics.RectF;
import android.graphics.drawable.Drawable;
import android.os.Build;
import android.os.Bundle;
import android.os.PowerManager;
import android.os.SystemClock;
import android.text.Editable;
import android.text.InputFilter;
import android.text.Selection;
import android.text.SpannableStringBuilder;
import android.text.TextWatcher;
import android.text.style.ImageSpan;
import android.util.Property;
import android.view.KeyEvent;
import android.view.MotionEvent;
import android.view.View;
import android.view.accessibility.AccessibilityManager;
import android.view.accessibility.AccessibilityNodeInfo;
import android.view.animation.AccelerateInterpolator;
import android.view.animation.DecelerateInterpolator;
import android.view.inputmethod.EditorInfo;
import android.view.inputmethod.InputConnection;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.TextView;
import androidx.core.os.BuildCompat;
import androidx.core.view.ViewCompat;
import androidx.core.view.accessibility.AccessibilityNodeInfoCompat;
import androidx.core.view.inputmethod.EditorInfoCompat;
import androidx.core.view.inputmethod.InputConnectionCompat;
import androidx.core.view.inputmethod.InputContentInfoCompat;
import androidx.customview.widget.ExploreByTouchHelper;
import com.google.android.exoplayer2.C;
import com.google.android.exoplayer2.DefaultRenderersFactory;
import com.google.android.exoplayer2.text.ttml.TtmlNode;
import com.google.android.exoplayer2.util.Log;
import com.google.firebase.remoteconfig.FirebaseRemoteConfig;
import im.uwrkaxlmjj.messenger.AccountInstance;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.ApplicationLoader;
import im.uwrkaxlmjj.messenger.BuildVars;
import im.uwrkaxlmjj.messenger.ChatObject;
import im.uwrkaxlmjj.messenger.Emoji;
import im.uwrkaxlmjj.messenger.FileLog;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.messenger.MediaController;
import im.uwrkaxlmjj.messenger.MediaDataController;
import im.uwrkaxlmjj.messenger.MessageObject;
import im.uwrkaxlmjj.messenger.MessagesController;
import im.uwrkaxlmjj.messenger.NotificationCenter;
import im.uwrkaxlmjj.messenger.NotificationsController;
import im.uwrkaxlmjj.messenger.SendMessagesHelper;
import im.uwrkaxlmjj.messenger.SharedConfig;
import im.uwrkaxlmjj.messenger.UserConfig;
import im.uwrkaxlmjj.messenger.UserObject;
import im.uwrkaxlmjj.messenger.VideoEditedInfo;
import im.uwrkaxlmjj.messenger.camera.CameraController;
import im.uwrkaxlmjj.messenger.utils.RegexUtils;
import im.uwrkaxlmjj.tgnet.ConnectionsManager;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.ui.ChatActivity;
import im.uwrkaxlmjj.ui.DialogsActivity;
import im.uwrkaxlmjj.ui.GroupStickersActivity;
import im.uwrkaxlmjj.ui.LaunchActivity;
import im.uwrkaxlmjj.ui.StickersActivity;
import im.uwrkaxlmjj.ui.actionbar.ActionBar;
import im.uwrkaxlmjj.ui.actionbar.ActionBarPopupWindow;
import im.uwrkaxlmjj.ui.actionbar.AlertDialog;
import im.uwrkaxlmjj.ui.actionbar.SimpleTextView;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.components.AlertsCreator;
import im.uwrkaxlmjj.ui.components.BotKeyboardView;
import im.uwrkaxlmjj.ui.components.EditTextCaption;
import im.uwrkaxlmjj.ui.components.EmojiView;
import im.uwrkaxlmjj.ui.components.EnterMenuView;
import im.uwrkaxlmjj.ui.components.SeekBar;
import im.uwrkaxlmjj.ui.components.SizeNotifierFrameLayout;
import im.uwrkaxlmjj.ui.components.StickersAlert;
import im.uwrkaxlmjj.ui.components.TextStyleSpan;
import im.uwrkaxlmjj.ui.components.VideoTimelineView;
import im.uwrkaxlmjj.ui.components.mentionspan.MentionSpanWatcher;
import im.uwrkaxlmjj.ui.components.toast.ToastUtils;
import im.uwrkaxlmjj.ui.constants.ChatEnterMenuType;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.edittext.NoCopySpanEditableFactory;
import im.uwrkaxlmjj.ui.hui.visualcall.PermissionUtils;
import im.uwrkaxlmjj.ui.hui.wallet_public.utils.WalletDialogUtil;
import im.uwrkaxlmjj.ui.hviews.MryRoundButtonDrawable;
import java.io.File;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import mpEIGo.juqQQs.esbSDO.R;
import org.webrtc.mozi.JavaScreenCapturer;

/* JADX INFO: loaded from: classes5.dex */
public class ChatActivityEnterView extends FrameLayout implements NotificationCenter.NotificationCenterDelegate, SizeNotifierFrameLayout.SizeNotifierFrameLayoutDelegate, StickersAlert.StickersAlertDelegate {
    private AccountInstance accountInstance;
    private boolean allowGifs;
    private boolean allowShowTopView;
    private boolean allowStickers;
    private ImageView attachButton;
    private ArrayList<Integer> attachIcons;
    private LinearLayout attachLayout;
    private ArrayList<String> attachTexts;
    private ArrayList<ChatEnterMenuType> attachTypes;
    private ImageView audioSendButton;
    private TLRPC.TL_document audioToSend;
    private MessageObject audioToSendMessageObject;
    private String audioToSendPath;
    private AnimatorSet audioVideoButtonAnimation;
    private FrameLayout audioVideoButtonContainer;
    private ImageView botButton;
    private MessageObject botButtonsMessageObject;
    private int botCount;
    private BotKeyboardView botKeyboardView;
    private MessageObject botMessageObject;
    private TLRPC.TL_replyKeyboardMarkup botReplyMarkup;
    private boolean calledRecordRunnable;
    private Drawable cameraDrawable;
    private boolean canWriteToChannel;
    private ImageView cancelBotButton;
    private boolean closeAnimationInProgress;
    private int currentAccount;
    private int currentEmojiIcon;
    private int currentPopupContentType;
    private Animator currentResizeAnimation;
    private AnimatorSet currentTopViewAnimation;
    private ChatActivityEnterViewDelegate delegate;
    private boolean destroyed;
    private long dialog_id;
    private float distCanMove;
    private AnimatorSet doneButtonAnimation;
    private FrameLayout doneButtonContainer;
    private ImageView doneButtonImage;
    private ContextProgressView doneButtonProgress;
    private Paint dotPaint;
    private boolean editingCaption;
    private MessageObject editingMessageObject;
    private int editingMessageReqId;
    private ImageView[] emojiButton;
    private AnimatorSet emojiButtonAnimation;
    private int emojiPadding;
    private boolean emojiTabOpen;
    private EmojiView emojiView;
    private boolean emojiViewVisible;
    private ImageView expandStickersButton;
    private Runnable focusRunnable;
    private boolean forceShowSendButton;
    private boolean gifsTabOpen;
    private boolean hasBotCommands;
    private boolean hasRecordVideo;
    private boolean ignoreTextChange;
    private Drawable inactinveSendButtonDrawable;
    private TLRPC.ChatFull info;
    private int innerTextChange;
    private boolean isPaused;
    private int keyboardHeight;
    private int keyboardHeightLand;
    private boolean keyboardVisible;
    private int lastSizeChangeValue1;
    private boolean lastSizeChangeValue2;
    private String lastTimeString;
    private long lastTypingSendTime;
    private long lastTypingTimeSend;
    private Drawable lockArrowDrawable;
    private Drawable lockBackgroundDrawable;
    private Drawable lockDrawable;
    private Drawable lockShadowDrawable;
    private Drawable lockTopDrawable;
    private View.AccessibilityDelegate mediaMessageButtonsDelegate;
    private EnterMenuView menuView;
    private boolean menuViewVisible;
    private EditTextCaption messageEditText;
    private TLRPC.WebPage messageWebPage;
    private boolean messageWebPageSearch;
    private Drawable micDrawable;
    private boolean needShowTopView;
    private ImageView notifyButton;
    private Runnable onFinishInitCameraRunnable;
    private Runnable openKeyboardRunnable;
    private int originalViewHeight;
    private Paint paint;
    private Paint paintRecord;
    private Activity parentActivity;
    private ChatActivity parentFragment;
    private Drawable pauseDrawable;
    private TLRPC.KeyboardButton pendingLocationButton;
    private MessageObject pendingMessageObject;
    private Drawable playDrawable;
    private CloseProgressDrawable2 progressDrawable;
    private Runnable recordAudioVideoRunnable;
    private boolean recordAudioVideoRunnableStarted;
    private ImageView recordCancelImage;
    private TextView recordCancelText;
    private RecordCircle recordCircle;
    private Property<RecordCircle, Float> recordCircleScale;
    private ImageView recordDeleteImageView;
    private RecordDot recordDot;
    private int recordInterfaceState;
    private FrameLayout recordPanel;
    private TextView recordSendText;
    private LinearLayout recordTimeContainer;
    private TextView recordTimeText;
    private View recordedAudioBackground;
    private FrameLayout recordedAudioPanel;
    private ImageView recordedAudioPlayButton;
    private SeekBarWaveformView recordedAudioSeekBar;
    private TextView recordedAudioTimeTextView;
    private boolean recordingAudioVideo;
    private int recordingGuid;
    private RectF rect;
    private Paint redDotPaint;
    private MessageObject replyingMessageObject;
    private Property<View, Integer> roundedTranslationYProperty;
    private AnimatorSet runningAnimation;
    private AnimatorSet runningAnimation2;
    private AnimatorSet runningAnimationAudio;
    private int runningAnimationType;
    private boolean scheduleButtonHidden;
    private ImageView scheduledButton;
    private AnimatorSet scheduledButtonAnimation;
    private int searchingType;
    private SeekBarWaveform seekBarWaveform;
    private View sendButton;
    private FrameLayout sendButtonContainer;
    private Drawable sendButtonDrawable;
    private Drawable sendButtonInverseDrawable;
    private boolean sendByEnter;
    private Drawable sendDrawable;
    private ActionBarPopupWindow.ActionBarPopupWindowLayout sendPopupLayout;
    private ActionBarPopupWindow sendPopupWindow;
    private boolean showKeyboardOnResume;
    private boolean silent;
    private SizeNotifierFrameLayout sizeNotifierLayout;
    private LinearLayout slideText;
    private SimpleTextView slowModeButton;
    private int slowModeTimer;
    private float startedDraggingX;
    private AnimatedArrowDrawable stickersArrow;
    private boolean stickersDragging;
    private boolean stickersExpanded;
    private int stickersExpandedHeight;
    private Animator stickersExpansionAnim;
    private float stickersExpansionProgress;
    private boolean stickersTabOpen;
    private LinearLayout textFieldContainer;
    private View topLineView;
    private View topView;
    private boolean topViewShowed;
    private Runnable updateExpandabilityRunnable;
    private Runnable updateSlowModeRunnable;
    private ImageView videoSendButton;
    private VideoTimelineView videoTimelineView;
    private VideoEditedInfo videoToSendMessageObject;
    private boolean waitingForKeyboardOpen;
    private PowerManager.WakeLock wakeLock;

    public interface ChatActivityEnterViewDelegate {
        void didPressedAttachButton(int i, ChatEnterMenuType chatEnterMenuType);

        boolean hasScheduledMessages();

        void needChangeVideoPreviewState(int i, float f);

        void needSendTyping();

        void needShowMediaBanHint();

        void needStartRecordAudio(int i);

        void needStartRecordVideo(int i, boolean z, int i2);

        void onAttachButtonHidden();

        void onAttachButtonShow();

        void onMessageEditEnd(boolean z);

        void onMessageSend(CharSequence charSequence, boolean z, int i);

        void onPreAudioVideoRecord();

        void onStickersExpandedChange();

        void onStickersTab(boolean z);

        void onSwitchRecordMode(boolean z);

        void onTextChanged(CharSequence charSequence, boolean z);

        void onTextSelectionChanged(int i, int i2);

        void onTextSpansChanged(CharSequence charSequence);

        void onUpdateSlowModeButton(View view, boolean z, CharSequence charSequence);

        void onWindowSizeChanged(int i);

        void openScheduledMessages();

        void scrollToSendingMessage();

        /* JADX INFO: renamed from: im.uwrkaxlmjj.ui.components.ChatActivityEnterView$ChatActivityEnterViewDelegate$-CC, reason: invalid class name */
        public final /* synthetic */ class CC {
            public static void $default$scrollToSendingMessage(ChatActivityEnterViewDelegate _this) {
            }

            public static void $default$openScheduledMessages(ChatActivityEnterViewDelegate _this) {
            }

            public static boolean $default$hasScheduledMessages(ChatActivityEnterViewDelegate _this) {
                return true;
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    class SeekBarWaveformView extends View {
        public SeekBarWaveformView(Context context) {
            super(context);
            ChatActivityEnterView.this.seekBarWaveform = new SeekBarWaveform(context);
            ChatActivityEnterView.this.seekBarWaveform.setDelegate(new SeekBar.SeekBarDelegate() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$ChatActivityEnterView$SeekBarWaveformView$p10IjL0B4WUd9RIBBxsqjXjcRbc
                @Override // im.uwrkaxlmjj.ui.components.SeekBar.SeekBarDelegate
                public /* synthetic */ void onSeekBarContinuousDrag(float f) {
                    SeekBar.SeekBarDelegate.CC.$default$onSeekBarContinuousDrag(this, f);
                }

                @Override // im.uwrkaxlmjj.ui.components.SeekBar.SeekBarDelegate
                public final void onSeekBarDrag(float f) {
                    this.f$0.lambda$new$0$ChatActivityEnterView$SeekBarWaveformView(f);
                }
            });
        }

        public /* synthetic */ void lambda$new$0$ChatActivityEnterView$SeekBarWaveformView(float progress) {
            if (ChatActivityEnterView.this.audioToSendMessageObject != null) {
                ChatActivityEnterView.this.audioToSendMessageObject.audioProgress = progress;
                MediaController.getInstance().seekToProgress(ChatActivityEnterView.this.audioToSendMessageObject, progress);
            }
        }

        public void setWaveform(byte[] waveform) {
            ChatActivityEnterView.this.seekBarWaveform.setWaveform(waveform);
            invalidate();
        }

        public void setProgress(float progress) {
            ChatActivityEnterView.this.seekBarWaveform.setProgress(progress);
            invalidate();
        }

        public boolean isDragging() {
            return ChatActivityEnterView.this.seekBarWaveform.isDragging();
        }

        @Override // android.view.View
        public boolean onTouchEvent(MotionEvent event) {
            boolean result = ChatActivityEnterView.this.seekBarWaveform.onTouch(event.getAction(), event.getX(), event.getY());
            if (result) {
                if (event.getAction() == 0) {
                    ChatActivityEnterView.this.requestDisallowInterceptTouchEvent(true);
                }
                invalidate();
            }
            return result || super.onTouchEvent(event);
        }

        @Override // android.view.View
        protected void onLayout(boolean changed, int left, int top, int right, int bottom) {
            super.onLayout(changed, left, top, right, bottom);
            ChatActivityEnterView.this.seekBarWaveform.setSize(right - left, bottom - top);
        }

        @Override // android.view.View
        protected void onDraw(Canvas canvas) {
            super.onDraw(canvas);
            ChatActivityEnterView.this.seekBarWaveform.setColors(Theme.getColor(Theme.key_chat_recordedVoiceProgress), Theme.getColor(Theme.key_chat_recordedVoiceProgressInner), Theme.getColor(Theme.key_chat_recordedVoiceProgress));
            ChatActivityEnterView.this.seekBarWaveform.draw(canvas);
        }
    }

    private class RecordDot extends View {
        private float alpha;
        private boolean isIncr;
        private long lastUpdateTime;

        public RecordDot(Context context) {
            super(context);
            ChatActivityEnterView.this.redDotPaint.setColor(Theme.getColor(Theme.key_chat_recordedVoiceDot));
        }

        public void resetAlpha() {
            this.alpha = 1.0f;
            this.lastUpdateTime = System.currentTimeMillis();
            this.isIncr = false;
            invalidate();
        }

        @Override // android.view.View
        protected void onDraw(Canvas canvas) {
            ChatActivityEnterView.this.redDotPaint.setAlpha((int) (this.alpha * 255.0f));
            long dt = System.currentTimeMillis() - this.lastUpdateTime;
            if (!this.isIncr) {
                float f = this.alpha - (dt / 400.0f);
                this.alpha = f;
                if (f <= 0.0f) {
                    this.alpha = 0.0f;
                    this.isIncr = true;
                }
            } else {
                float f2 = this.alpha + (dt / 400.0f);
                this.alpha = f2;
                if (f2 >= 1.0f) {
                    this.alpha = 1.0f;
                    this.isIncr = false;
                }
            }
            this.lastUpdateTime = System.currentTimeMillis();
            canvas.drawCircle(AndroidUtilities.dp(5.0f), AndroidUtilities.dp(5.0f), AndroidUtilities.dp(5.0f), ChatActivityEnterView.this.redDotPaint);
            invalidate();
        }
    }

    private class RecordCircle extends View {
        private float amplitude;
        private float animateAmplitudeDiff;
        private float animateToAmplitude;
        private long lastUpdateTime;
        private float lockAnimatedTranslation;
        private boolean pressed;
        private float scale;
        private boolean sendButtonVisible;
        private float startTranslation;
        private VirtualViewHelper virtualViewHelper;

        public RecordCircle(Context context) {
            super(context);
            ChatActivityEnterView.this.paint.setColor(Theme.getColor(Theme.key_chat_messagePanelVoiceBackground));
            ChatActivityEnterView.this.paintRecord.setColor(Theme.getColor(Theme.key_chat_messagePanelVoiceShadow));
            ChatActivityEnterView.this.lockDrawable = getResources().getDrawable(R.drawable.lock_middle);
            ChatActivityEnterView.this.lockDrawable.setColorFilter(new PorterDuffColorFilter(Theme.getColor(Theme.key_chat_messagePanelVoiceLock), PorterDuff.Mode.MULTIPLY));
            ChatActivityEnterView.this.lockTopDrawable = getResources().getDrawable(R.drawable.lock_top);
            ChatActivityEnterView.this.lockTopDrawable.setColorFilter(new PorterDuffColorFilter(Theme.getColor(Theme.key_chat_messagePanelVoiceLock), PorterDuff.Mode.MULTIPLY));
            ChatActivityEnterView.this.lockArrowDrawable = getResources().getDrawable(R.drawable.lock_arrow);
            ChatActivityEnterView.this.lockArrowDrawable.setColorFilter(new PorterDuffColorFilter(Theme.getColor(Theme.key_chat_messagePanelVoiceLock), PorterDuff.Mode.MULTIPLY));
            ChatActivityEnterView.this.lockBackgroundDrawable = getResources().getDrawable(R.drawable.lock_round);
            ChatActivityEnterView.this.lockBackgroundDrawable.setColorFilter(new PorterDuffColorFilter(Theme.getColor(Theme.key_chat_messagePanelVoiceLockBackground), PorterDuff.Mode.MULTIPLY));
            ChatActivityEnterView.this.lockShadowDrawable = getResources().getDrawable(R.drawable.lock_round_shadow);
            ChatActivityEnterView.this.lockShadowDrawable.setColorFilter(new PorterDuffColorFilter(Theme.getColor(Theme.key_chat_messagePanelVoiceLockShadow), PorterDuff.Mode.MULTIPLY));
            ChatActivityEnterView.this.micDrawable = getResources().getDrawable(R.drawable.input_mic).mutate();
            ChatActivityEnterView.this.micDrawable.setColorFilter(new PorterDuffColorFilter(Theme.getColor(Theme.key_chat_messagePanelVoicePressed), PorterDuff.Mode.SRC_IN));
            ChatActivityEnterView.this.cameraDrawable = getResources().getDrawable(R.drawable.input_video).mutate();
            ChatActivityEnterView.this.cameraDrawable.setColorFilter(new PorterDuffColorFilter(Theme.getColor(Theme.key_chat_messagePanelVoicePressed), PorterDuff.Mode.MULTIPLY));
            ChatActivityEnterView.this.sendDrawable = getResources().getDrawable(R.drawable.ic_send).mutate();
            ChatActivityEnterView.this.sendDrawable.setColorFilter(new PorterDuffColorFilter(Theme.getColor(Theme.key_chat_messagePanelVoicePressed), PorterDuff.Mode.MULTIPLY));
            VirtualViewHelper virtualViewHelper = new VirtualViewHelper(this);
            this.virtualViewHelper = virtualViewHelper;
            ViewCompat.setAccessibilityDelegate(this, virtualViewHelper);
        }

        public void setAmplitude(double value) {
            float fMin = ((float) Math.min(100.0d, value)) / 100.0f;
            this.animateToAmplitude = fMin;
            this.animateAmplitudeDiff = (fMin - this.amplitude) / 150.0f;
            this.lastUpdateTime = System.currentTimeMillis();
            invalidate();
        }

        public float getScale() {
            return this.scale;
        }

        public void setScale(float value) {
            this.scale = value;
            invalidate();
        }

        public void setLockAnimatedTranslation(float value) {
            this.lockAnimatedTranslation = value;
            invalidate();
        }

        public float getLockAnimatedTranslation() {
            return this.lockAnimatedTranslation;
        }

        public boolean isSendButtonVisible() {
            return this.sendButtonVisible;
        }

        public void setSendButtonInvisible() {
            this.sendButtonVisible = false;
            invalidate();
        }

        public int setLockTranslation(float value) {
            if (value == 10000.0f) {
                this.sendButtonVisible = false;
                this.lockAnimatedTranslation = -1.0f;
                this.startTranslation = -1.0f;
                invalidate();
                return 0;
            }
            if (this.sendButtonVisible) {
                return 2;
            }
            if (this.lockAnimatedTranslation == -1.0f) {
                this.startTranslation = value;
            }
            this.lockAnimatedTranslation = value;
            invalidate();
            if (this.startTranslation - this.lockAnimatedTranslation < AndroidUtilities.dp(57.0f)) {
                return 1;
            }
            this.sendButtonVisible = true;
            return 2;
        }

        @Override // android.view.View
        public boolean onTouchEvent(MotionEvent event) {
            if (this.sendButtonVisible) {
                int x = (int) event.getX();
                int y = (int) event.getY();
                if (event.getAction() == 0) {
                    boolean zContains = ChatActivityEnterView.this.lockBackgroundDrawable.getBounds().contains(x, y);
                    this.pressed = zContains;
                    return zContains;
                }
                if (this.pressed) {
                    if (event.getAction() == 1 && ChatActivityEnterView.this.lockBackgroundDrawable.getBounds().contains(x, y)) {
                        if (ChatActivityEnterView.this.videoSendButton != null && ChatActivityEnterView.this.videoSendButton.getTag() != null) {
                            ChatActivityEnterView.this.delegate.needStartRecordVideo(3, true, 0);
                        } else {
                            MediaController.getInstance().stopRecording(2, true, 0);
                            ChatActivityEnterView.this.delegate.needStartRecordAudio(0);
                        }
                    }
                    return true;
                }
            }
            return false;
        }

        @Override // android.view.View
        protected void onDraw(Canvas canvas) {
            float sc;
            float alpha;
            int lockSize;
            int lockTopY;
            int lockMiddleY;
            int lockArrowY;
            int lockY;
            int cx = getMeasuredWidth() / 2;
            int cy = AndroidUtilities.dp(170.0f);
            float yAdd = 0.0f;
            float f = this.lockAnimatedTranslation;
            if (f != 10000.0f) {
                yAdd = Math.max(0, (int) (this.startTranslation - f));
                if (yAdd > AndroidUtilities.dp(57.0f)) {
                    yAdd = AndroidUtilities.dp(57.0f);
                }
            }
            int cy2 = (int) (cy - yAdd);
            float f2 = this.scale;
            if (f2 <= 0.5f) {
                alpha = f2 / 0.5f;
                sc = alpha;
            } else if (f2 <= 0.75f) {
                sc = 1.0f - (((f2 - 0.5f) / 0.25f) * 0.1f);
                alpha = 1.0f;
            } else {
                sc = 0.9f + (((f2 - 0.75f) / 0.25f) * 0.1f);
                alpha = 1.0f;
            }
            long dt = System.currentTimeMillis() - this.lastUpdateTime;
            float f3 = this.animateToAmplitude;
            float f4 = this.amplitude;
            if (f3 != f4) {
                float f5 = this.animateAmplitudeDiff;
                float f6 = f4 + (dt * f5);
                this.amplitude = f6;
                if (f5 > 0.0f) {
                    if (f6 > f3) {
                        this.amplitude = f3;
                    }
                } else if (f6 < f3) {
                    this.amplitude = f3;
                }
                invalidate();
            }
            this.lastUpdateTime = System.currentTimeMillis();
            if (this.amplitude != 0.0f) {
                canvas.drawCircle(getMeasuredWidth() / 2.0f, cy2, (AndroidUtilities.dp(42.0f) + (AndroidUtilities.dp(20.0f) * this.amplitude)) * this.scale, ChatActivityEnterView.this.paintRecord);
            }
            canvas.drawCircle(getMeasuredWidth() / 2.0f, cy2, AndroidUtilities.dp(42.0f) * sc, ChatActivityEnterView.this.paint);
            Drawable drawable = isSendButtonVisible() ? ChatActivityEnterView.this.sendDrawable : (ChatActivityEnterView.this.videoSendButton == null || ChatActivityEnterView.this.videoSendButton.getTag() == null) ? ChatActivityEnterView.this.micDrawable : ChatActivityEnterView.this.cameraDrawable;
            drawable.setBounds(cx - (drawable.getIntrinsicWidth() / 2), cy2 - (drawable.getIntrinsicHeight() / 2), (drawable.getIntrinsicWidth() / 2) + cx, (drawable.getIntrinsicHeight() / 2) + cy2);
            drawable.setAlpha((int) (alpha * 255.0f));
            drawable.draw(canvas);
            float moveProgress = 1.0f - (yAdd / AndroidUtilities.dp(57.0f));
            float moveProgress2 = Math.max(0.0f, 1.0f - ((yAdd / AndroidUtilities.dp(57.0f)) * 2.0f));
            int intAlpha = (int) (255.0f * alpha);
            if (isSendButtonVisible()) {
                lockSize = AndroidUtilities.dp(31.0f);
                int lockY2 = AndroidUtilities.dp(57.0f) + ((int) (((AndroidUtilities.dp(30.0f) * (1.0f - sc)) - yAdd) + (AndroidUtilities.dp(20.0f) * moveProgress)));
                lockTopY = lockY2 + AndroidUtilities.dp(5.0f);
                lockMiddleY = lockY2 + AndroidUtilities.dp(11.0f);
                int lockArrowY2 = lockY2 + AndroidUtilities.dp(25.0f);
                intAlpha = (int) (intAlpha * (yAdd / AndroidUtilities.dp(57.0f)));
                ChatActivityEnterView.this.lockBackgroundDrawable.setAlpha(255);
                ChatActivityEnterView.this.lockShadowDrawable.setAlpha(255);
                ChatActivityEnterView.this.lockTopDrawable.setAlpha(intAlpha);
                ChatActivityEnterView.this.lockDrawable.setAlpha(intAlpha);
                ChatActivityEnterView.this.lockArrowDrawable.setAlpha((int) (intAlpha * moveProgress2));
                lockArrowY = lockArrowY2;
                lockY = lockY2;
            } else {
                int cy3 = AndroidUtilities.dp(31.0f);
                lockSize = cy3 + ((int) (AndroidUtilities.dp(29.0f) * moveProgress));
                int lockY3 = (AndroidUtilities.dp(57.0f) + ((int) (AndroidUtilities.dp(30.0f) * (1.0f - sc)))) - ((int) yAdd);
                lockTopY = lockY3 + AndroidUtilities.dp(5.0f) + ((int) (AndroidUtilities.dp(4.0f) * moveProgress));
                lockMiddleY = lockY3 + AndroidUtilities.dp(11.0f) + ((int) (AndroidUtilities.dp(10.0f) * moveProgress));
                int lockArrowY3 = lockY3 + AndroidUtilities.dp(25.0f) + ((int) (AndroidUtilities.dp(16.0f) * moveProgress));
                ChatActivityEnterView.this.lockBackgroundDrawable.setAlpha(intAlpha);
                ChatActivityEnterView.this.lockShadowDrawable.setAlpha(intAlpha);
                ChatActivityEnterView.this.lockTopDrawable.setAlpha(intAlpha);
                ChatActivityEnterView.this.lockDrawable.setAlpha(intAlpha);
                ChatActivityEnterView.this.lockArrowDrawable.setAlpha((int) (intAlpha * moveProgress2));
                lockArrowY = lockArrowY3;
                lockY = lockY3;
            }
            ChatActivityEnterView.this.lockBackgroundDrawable.setBounds(cx - AndroidUtilities.dp(15.0f), lockY, cx + AndroidUtilities.dp(15.0f), lockY + lockSize);
            ChatActivityEnterView.this.lockBackgroundDrawable.draw(canvas);
            ChatActivityEnterView.this.lockShadowDrawable.setBounds(cx - AndroidUtilities.dp(16.0f), lockY - AndroidUtilities.dp(1.0f), cx + AndroidUtilities.dp(16.0f), lockY + lockSize + AndroidUtilities.dp(1.0f));
            ChatActivityEnterView.this.lockShadowDrawable.draw(canvas);
            ChatActivityEnterView.this.lockTopDrawable.setBounds(cx - AndroidUtilities.dp(6.0f), lockTopY, AndroidUtilities.dp(6.0f) + cx, AndroidUtilities.dp(14.0f) + lockTopY);
            ChatActivityEnterView.this.lockTopDrawable.draw(canvas);
            ChatActivityEnterView.this.lockDrawable.setBounds(cx - AndroidUtilities.dp(7.0f), lockMiddleY, AndroidUtilities.dp(7.0f) + cx, AndroidUtilities.dp(12.0f) + lockMiddleY);
            ChatActivityEnterView.this.lockDrawable.draw(canvas);
            ChatActivityEnterView.this.lockArrowDrawable.setBounds(cx - AndroidUtilities.dp(7.5f), lockArrowY, AndroidUtilities.dp(7.5f) + cx, AndroidUtilities.dp(9.0f) + lockArrowY);
            ChatActivityEnterView.this.lockArrowDrawable.draw(canvas);
            if (isSendButtonVisible()) {
                ChatActivityEnterView.this.redDotPaint.setAlpha(255);
                ChatActivityEnterView.this.rect.set(cx - AndroidUtilities.dp2(6.5f), AndroidUtilities.dp(9.0f) + lockY, AndroidUtilities.dp(6.5f) + cx, AndroidUtilities.dp(22.0f) + lockY);
                canvas.drawRoundRect(ChatActivityEnterView.this.rect, AndroidUtilities.dp(1.0f), AndroidUtilities.dp(1.0f), ChatActivityEnterView.this.redDotPaint);
            }
        }

        @Override // android.view.View
        protected boolean dispatchHoverEvent(MotionEvent event) {
            return super.dispatchHoverEvent(event) || this.virtualViewHelper.dispatchHoverEvent(event);
        }

        private class VirtualViewHelper extends ExploreByTouchHelper {
            public VirtualViewHelper(View host) {
                super(host);
            }

            @Override // androidx.customview.widget.ExploreByTouchHelper
            protected int getVirtualViewAt(float x, float y) {
                if (RecordCircle.this.isSendButtonVisible()) {
                    if (!ChatActivityEnterView.this.sendDrawable.getBounds().contains((int) x, (int) y)) {
                        if (ChatActivityEnterView.this.lockBackgroundDrawable.getBounds().contains((int) x, (int) y)) {
                            return 2;
                        }
                        return -1;
                    }
                    return 1;
                }
                return -1;
            }

            @Override // androidx.customview.widget.ExploreByTouchHelper
            protected void getVisibleVirtualViews(List<Integer> list) {
                if (RecordCircle.this.isSendButtonVisible()) {
                    list.add(1);
                    list.add(2);
                }
            }

            @Override // androidx.customview.widget.ExploreByTouchHelper
            protected void onPopulateNodeForVirtualView(int id, AccessibilityNodeInfoCompat info) {
                if (id == 1) {
                    info.setBoundsInParent(ChatActivityEnterView.this.sendDrawable.getBounds());
                    info.setText(LocaleController.getString("Send", R.string.Send));
                } else if (id == 2) {
                    info.setBoundsInParent(ChatActivityEnterView.this.lockBackgroundDrawable.getBounds());
                    info.setText(LocaleController.getString("Stop", R.string.Stop));
                }
            }

            @Override // androidx.customview.widget.ExploreByTouchHelper
            protected boolean onPerformActionForVirtualView(int id, int action, Bundle args) {
                return true;
            }
        }
    }

    public ChatActivityEnterView(Activity context, SizeNotifierFrameLayout parent, ChatActivity fragment, boolean isChat) {
        int i;
        String str;
        ChatActivityEnterViewDelegate chatActivityEnterViewDelegate;
        super(context);
        this.currentAccount = UserConfig.selectedAccount;
        this.accountInstance = AccountInstance.getInstance(UserConfig.selectedAccount);
        this.mediaMessageButtonsDelegate = new View.AccessibilityDelegate() { // from class: im.uwrkaxlmjj.ui.components.ChatActivityEnterView.1
            @Override // android.view.View.AccessibilityDelegate
            public void onInitializeAccessibilityNodeInfo(View host, AccessibilityNodeInfo info) {
                super.onInitializeAccessibilityNodeInfo(host, info);
                info.setClassName("android.widget.ImageButton");
                info.setClickable(true);
                info.setLongClickable(true);
            }
        };
        this.emojiButton = new ImageView[2];
        this.currentPopupContentType = -1;
        this.currentEmojiIcon = -1;
        this.isPaused = true;
        this.startedDraggingX = -1.0f;
        this.distCanMove = AndroidUtilities.dp(80.0f);
        this.messageWebPageSearch = true;
        this.openKeyboardRunnable = new Runnable() { // from class: im.uwrkaxlmjj.ui.components.ChatActivityEnterView.2
            @Override // java.lang.Runnable
            public void run() {
                if (!ChatActivityEnterView.this.destroyed && ChatActivityEnterView.this.messageEditText != null && ChatActivityEnterView.this.waitingForKeyboardOpen && !ChatActivityEnterView.this.keyboardVisible && !AndroidUtilities.usingHardwareInput && !AndroidUtilities.isInMultiwindow) {
                    ChatActivityEnterView.this.messageEditText.requestFocus();
                    AndroidUtilities.showKeyboard(ChatActivityEnterView.this.messageEditText);
                    AndroidUtilities.cancelRunOnUIThread(ChatActivityEnterView.this.openKeyboardRunnable);
                    AndroidUtilities.runOnUIThread(ChatActivityEnterView.this.openKeyboardRunnable, 100L);
                }
            }
        };
        this.updateExpandabilityRunnable = new Runnable() { // from class: im.uwrkaxlmjj.ui.components.ChatActivityEnterView.3
            private int lastKnownPage = -1;

            @Override // java.lang.Runnable
            public void run() {
                int curPage;
                if (ChatActivityEnterView.this.emojiView != null && (curPage = ChatActivityEnterView.this.emojiView.getCurrentPage()) != this.lastKnownPage) {
                    this.lastKnownPage = curPage;
                    boolean prevOpen = ChatActivityEnterView.this.stickersTabOpen;
                    ChatActivityEnterView.this.stickersTabOpen = curPage == 1 || curPage == 2;
                    boolean prevOpen2 = ChatActivityEnterView.this.emojiTabOpen;
                    ChatActivityEnterView.this.emojiTabOpen = curPage == 0;
                    if (ChatActivityEnterView.this.stickersExpanded) {
                        if (ChatActivityEnterView.this.stickersTabOpen || ChatActivityEnterView.this.searchingType != 0) {
                            if (ChatActivityEnterView.this.searchingType != 0) {
                                ChatActivityEnterView.this.searchingType = curPage != 0 ? 1 : 2;
                                ChatActivityEnterView.this.checkStickresExpandHeight();
                            }
                        } else {
                            if (ChatActivityEnterView.this.searchingType != 0) {
                                ChatActivityEnterView.this.searchingType = 0;
                                ChatActivityEnterView.this.emojiView.closeSearch(true);
                                ChatActivityEnterView.this.emojiView.hideSearchKeyboard();
                            }
                            ChatActivityEnterView.this.setStickersExpanded(false, true, false);
                        }
                    }
                    if (prevOpen != ChatActivityEnterView.this.stickersTabOpen || prevOpen2 != ChatActivityEnterView.this.emojiTabOpen) {
                        ChatActivityEnterView.this.checkSendButton(true);
                    }
                }
            }
        };
        this.roundedTranslationYProperty = new Property<View, Integer>(Integer.class, "translationY") { // from class: im.uwrkaxlmjj.ui.components.ChatActivityEnterView.4
            @Override // android.util.Property
            public Integer get(View object) {
                return Integer.valueOf(Math.round(object.getTranslationY()));
            }

            @Override // android.util.Property
            public void set(View object, Integer value) {
                object.setTranslationY(value.intValue());
            }
        };
        this.recordCircleScale = new Property<RecordCircle, Float>(Float.class, "scale") { // from class: im.uwrkaxlmjj.ui.components.ChatActivityEnterView.5
            @Override // android.util.Property
            public Float get(RecordCircle object) {
                return Float.valueOf(object.getScale());
            }

            @Override // android.util.Property
            public void set(RecordCircle object, Float value) {
                object.setScale(value.floatValue());
            }
        };
        this.redDotPaint = new Paint(1);
        this.onFinishInitCameraRunnable = new Runnable() { // from class: im.uwrkaxlmjj.ui.components.ChatActivityEnterView.6
            @Override // java.lang.Runnable
            public void run() {
                if (ChatActivityEnterView.this.delegate != null) {
                    ChatActivityEnterView.this.delegate.needStartRecordVideo(0, true, 0);
                }
            }
        };
        this.recordAudioVideoRunnable = new Runnable() { // from class: im.uwrkaxlmjj.ui.components.ChatActivityEnterView.7
            @Override // java.lang.Runnable
            public void run() {
                if (ChatActivityEnterView.this.delegate != null && ChatActivityEnterView.this.parentActivity != null) {
                    ChatActivityEnterView.this.delegate.onPreAudioVideoRecord();
                    ChatActivityEnterView.this.calledRecordRunnable = true;
                    ChatActivityEnterView.this.recordAudioVideoRunnableStarted = false;
                    ChatActivityEnterView.this.recordCircle.setLockTranslation(10000.0f);
                    ChatActivityEnterView.this.recordSendText.setAlpha(0.0f);
                    ChatActivityEnterView.this.slideText.setAlpha(1.0f);
                    ChatActivityEnterView.this.slideText.setTranslationY(0.0f);
                    if (ChatActivityEnterView.this.videoSendButton == null || ChatActivityEnterView.this.videoSendButton.getTag() == null) {
                        if (ChatActivityEnterView.this.parentFragment == null || Build.VERSION.SDK_INT < 23 || ChatActivityEnterView.this.parentActivity.checkSelfPermission("android.permission.RECORD_AUDIO") == 0) {
                            ChatActivityEnterView.this.delegate.needStartRecordAudio(1);
                            ChatActivityEnterView.this.startedDraggingX = -1.0f;
                            MediaController.getInstance().startRecording(ChatActivityEnterView.this.currentAccount, ChatActivityEnterView.this.dialog_id, ChatActivityEnterView.this.replyingMessageObject, ChatActivityEnterView.this.recordingGuid);
                            ChatActivityEnterView.this.updateRecordIntefrace();
                            ChatActivityEnterView.this.audioVideoButtonContainer.getParent().requestDisallowInterceptTouchEvent(true);
                            return;
                        }
                        ChatActivityEnterView.this.parentActivity.requestPermissions(new String[]{"android.permission.RECORD_AUDIO"}, 3);
                        return;
                    }
                    if (Build.VERSION.SDK_INT >= 23) {
                        boolean hasAudio = ChatActivityEnterView.this.parentActivity.checkSelfPermission("android.permission.RECORD_AUDIO") == 0;
                        boolean hasVideo = ChatActivityEnterView.this.parentActivity.checkSelfPermission("android.permission.CAMERA") == 0;
                        if (!hasAudio || !hasVideo) {
                            String[] permissions = new String[(hasAudio || hasVideo) ? 1 : 2];
                            if (!hasAudio && !hasVideo) {
                                permissions[0] = "android.permission.RECORD_AUDIO";
                                permissions[1] = "android.permission.CAMERA";
                            } else if (!hasAudio) {
                                permissions[0] = "android.permission.RECORD_AUDIO";
                            } else {
                                permissions[0] = "android.permission.CAMERA";
                            }
                            ChatActivityEnterView.this.parentActivity.requestPermissions(permissions, 3);
                            return;
                        }
                    }
                    if (!CameraController.getInstance().isCameraInitied()) {
                        CameraController.getInstance().initCamera(ChatActivityEnterView.this.onFinishInitCameraRunnable);
                    } else {
                        ChatActivityEnterView.this.onFinishInitCameraRunnable.run();
                    }
                }
            }
        };
        this.paint = new Paint(1);
        this.paintRecord = new Paint(1);
        this.rect = new RectF();
        this.attachTexts = new ArrayList<>();
        this.attachIcons = new ArrayList<>();
        this.attachTypes = new ArrayList<>();
        Paint paint = new Paint(1);
        this.dotPaint = paint;
        paint.setColor(Theme.getColor(Theme.key_chat_emojiPanelNewTrending));
        setFocusable(true);
        setFocusableInTouchMode(true);
        setWillNotDraw(false);
        NotificationCenter.getInstance(this.currentAccount).addObserver(this, NotificationCenter.recordStarted);
        NotificationCenter.getInstance(this.currentAccount).addObserver(this, NotificationCenter.recordStartError);
        NotificationCenter.getInstance(this.currentAccount).addObserver(this, NotificationCenter.recordStopped);
        NotificationCenter.getInstance(this.currentAccount).addObserver(this, NotificationCenter.recordProgressChanged);
        NotificationCenter.getInstance(this.currentAccount).addObserver(this, NotificationCenter.closeChats);
        NotificationCenter.getInstance(this.currentAccount).addObserver(this, NotificationCenter.audioDidSent);
        NotificationCenter.getInstance(this.currentAccount).addObserver(this, NotificationCenter.audioRouteChanged);
        NotificationCenter.getInstance(this.currentAccount).addObserver(this, NotificationCenter.messagePlayingDidReset);
        NotificationCenter.getInstance(this.currentAccount).addObserver(this, NotificationCenter.messagePlayingProgressDidChanged);
        NotificationCenter.getInstance(this.currentAccount).addObserver(this, NotificationCenter.featuredStickersDidLoad);
        NotificationCenter.getInstance(this.currentAccount).addObserver(this, NotificationCenter.messageReceivedByServer);
        NotificationCenter.getInstance(this.currentAccount).addObserver(this, NotificationCenter.sendingMessagesChanged);
        NotificationCenter.getGlobalInstance().addObserver(this, NotificationCenter.emojiDidLoad);
        this.parentActivity = context;
        this.parentFragment = fragment;
        if (fragment != null) {
            this.recordingGuid = fragment.getClassGuid();
        }
        this.sizeNotifierLayout = parent;
        parent.setDelegate(this);
        SharedPreferences preferences = MessagesController.getGlobalMainSettings();
        this.sendByEnter = preferences.getBoolean("send_by_enter", false);
        LinearLayout linearLayout = new LinearLayout(context);
        this.textFieldContainer = linearLayout;
        linearLayout.setBackgroundColor(Theme.getColor(Theme.key_chat_emojiPanelBackground));
        this.textFieldContainer.setOrientation(0);
        this.textFieldContainer.setClipChildren(false);
        this.textFieldContainer.setClipToPadding(false);
        addView(this.textFieldContainer, LayoutHelper.createFrame(-1.0f, -2.0f, 83, 0.0f, 2.0f, 0.0f, 0.0f));
        FrameLayout frameLayout = new FrameLayout(context) { // from class: im.uwrkaxlmjj.ui.components.ChatActivityEnterView.8
            @Override // android.widget.FrameLayout, android.view.ViewGroup, android.view.View
            protected void onLayout(boolean changed, int left, int top, int right, int bottom) {
                super.onLayout(changed, left, top, right, bottom);
                if (ChatActivityEnterView.this.scheduledButton != null) {
                    int x = (getMeasuredWidth() - AndroidUtilities.dp((ChatActivityEnterView.this.botButton == null || ChatActivityEnterView.this.botButton.getVisibility() != 0) ? 48.0f : 96.0f)) - AndroidUtilities.dp(48.0f);
                    ChatActivityEnterView.this.scheduledButton.layout(x, ChatActivityEnterView.this.scheduledButton.getTop(), ChatActivityEnterView.this.scheduledButton.getMeasuredWidth() + x, ChatActivityEnterView.this.scheduledButton.getBottom());
                }
            }
        };
        this.textFieldContainer.addView(frameLayout, LayoutHelper.createLinear(0, -2, 1.0f, 80));
        AnonymousClass9 anonymousClass9 = new AnonymousClass9(context);
        this.messageEditText = anonymousClass9;
        anonymousClass9.setDelegate(new EditTextCaption.EditTextCaptionDelegate() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$ChatActivityEnterView$c1xjmuRKd7VkaxWmhYueJxd_Zp0
            @Override // im.uwrkaxlmjj.ui.components.EditTextCaption.EditTextCaptionDelegate
            public final void onSpansChanged() {
                this.f$0.lambda$new$0$ChatActivityEnterView();
            }
        });
        ChatActivity chatActivity = this.parentFragment;
        TLRPC.EncryptedChat encryptedChat = chatActivity != null ? chatActivity.getCurrentEncryptedChat() : null;
        this.messageEditText.setAllowTextEntitiesIntersection(encryptedChat == null || (encryptedChat != null && AndroidUtilities.getPeerLayerVersion(encryptedChat.layer) >= 101));
        updateFieldHint();
        int flags = C.ENCODING_PCM_MU_LAW;
        this.messageEditText.setImeOptions(encryptedChat != null ? 268435456 | 16777216 : flags);
        EditTextCaption editTextCaption = this.messageEditText;
        editTextCaption.setInputType(editTextCaption.getInputType() | 16384 | 131072);
        this.messageEditText.setSingleLine(false);
        this.messageEditText.setMaxLines(6);
        this.messageEditText.setTextSize(1, 18.0f);
        this.messageEditText.setGravity(16);
        this.messageEditText.setPadding(AndroidUtilities.dp(5.0f), AndroidUtilities.dp(2.0f), AndroidUtilities.dp(5.0f), AndroidUtilities.dp(2.0f));
        this.messageEditText.setMinimumHeight(AndroidUtilities.dp(38.0f));
        MryRoundButtonDrawable messageEditTextBackground = new MryRoundButtonDrawable();
        messageEditTextBackground.setIsRadiusAdjustBounds(false);
        messageEditTextBackground.setCornerRadius(AndroidUtilities.dp(8.0f));
        messageEditTextBackground.setBgData(ColorStateList.valueOf(Theme.getColor(Theme.key_windowBackgroundWhite)));
        messageEditTextBackground.setStrokeData(AndroidUtilities.dp(0.05f), ColorStateList.valueOf(Theme.getColor(Theme.key_divider)));
        this.messageEditText.setBackgroundDrawable(messageEditTextBackground);
        this.messageEditText.setTextColor(Theme.getColor(Theme.key_chat_messagePanelText));
        this.messageEditText.setHintColor(Theme.getColor(Theme.key_chat_messagePanelHint));
        this.messageEditText.setHintTextColor(Theme.getColor(Theme.key_chat_messagePanelHint));
        this.messageEditText.setCursorColor(Theme.getColor(Theme.key_chat_messagePanelCursor));
        frameLayout.addView(this.messageEditText, LayoutHelper.createFrame(-1.0f, -2.0f, 80, 52.0f, 5.0f, isChat ? 50.0f : 2.0f, 6.0f));
        this.messageEditText.setOnKeyListener(new View.OnKeyListener() { // from class: im.uwrkaxlmjj.ui.components.ChatActivityEnterView.10
            boolean ctrlPressed = false;

            @Override // android.view.View.OnKeyListener
            public boolean onKey(View view, int i2, KeyEvent keyEvent) {
                if (i2 == 4 && !ChatActivityEnterView.this.keyboardVisible && ChatActivityEnterView.this.isPopupShowing()) {
                    if (keyEvent.getAction() == 1) {
                        if (ChatActivityEnterView.this.currentPopupContentType == 1 && ChatActivityEnterView.this.botButtonsMessageObject != null) {
                            SharedPreferences preferences2 = MessagesController.getMainSettings(ChatActivityEnterView.this.currentAccount);
                            preferences2.edit().putInt("hidekeyboard_" + ChatActivityEnterView.this.dialog_id, ChatActivityEnterView.this.botButtonsMessageObject.getId()).commit();
                        }
                        if (ChatActivityEnterView.this.searchingType != 0) {
                            ChatActivityEnterView.this.searchingType = 0;
                            ChatActivityEnterView.this.emojiView.closeSearch(true);
                            ChatActivityEnterView.this.messageEditText.requestFocus();
                        } else {
                            ChatActivityEnterView.this.showPopup(0, 0);
                        }
                    }
                    return true;
                }
                if (i2 == 66 && ((this.ctrlPressed || ChatActivityEnterView.this.sendByEnter) && keyEvent.getAction() == 0 && ChatActivityEnterView.this.editingMessageObject == null)) {
                    if (ChatActivityEnterView.this.slowModeTimer <= 0) {
                        ChatActivityEnterView.this.sendMessage();
                    }
                    return true;
                }
                if (i2 == 113 || i2 == 114) {
                    this.ctrlPressed = keyEvent.getAction() == 0;
                    return true;
                }
                if (i2 == 67 && keyEvent.getAction() == 0) {
                    int selectionStart = Selection.getSelectionStart(ChatActivityEnterView.this.messageEditText.getText());
                    int selectionEnd = Selection.getSelectionEnd(ChatActivityEnterView.this.messageEditText.getText());
                    URLSpanUserMention[] spans = (URLSpanUserMention[]) ChatActivityEnterView.this.messageEditText.getText().getSpans(selectionStart, selectionEnd, URLSpanUserMention.class);
                    for (URLSpanUserMention span : spans) {
                        if (span != null && ChatActivityEnterView.this.messageEditText.getText().getSpanEnd(span) == selectionStart) {
                            int spanStart = ChatActivityEnterView.this.messageEditText.getText().getSpanStart(span);
                            int spanEnd = ChatActivityEnterView.this.messageEditText.getText().getSpanEnd(span);
                            Selection.setSelection(ChatActivityEnterView.this.messageEditText.getText(), spanStart, spanEnd);
                            return selectionStart == selectionEnd;
                        }
                    }
                    return false;
                }
                return false;
            }
        });
        this.messageEditText.setOnEditorActionListener(new TextView.OnEditorActionListener() { // from class: im.uwrkaxlmjj.ui.components.ChatActivityEnterView.11
            boolean ctrlPressed = false;

            @Override // android.widget.TextView.OnEditorActionListener
            public boolean onEditorAction(TextView textView, int i2, KeyEvent keyEvent) {
                if (i2 == 4) {
                    ChatActivityEnterView.this.sendMessage();
                    return true;
                }
                if (keyEvent != null && i2 == 0) {
                    if ((this.ctrlPressed || ChatActivityEnterView.this.sendByEnter) && keyEvent.getAction() == 0 && ChatActivityEnterView.this.editingMessageObject == null) {
                        ChatActivityEnterView.this.sendMessage();
                        return true;
                    }
                    if (i2 == 113 || i2 == 114) {
                        this.ctrlPressed = keyEvent.getAction() == 0;
                        return true;
                    }
                }
                return false;
            }
        });
        this.messageEditText.setEditableFactory(new NoCopySpanEditableFactory(new MentionSpanWatcher()));
        this.messageEditText.addTextChangedListener(new TextWatcher() { // from class: im.uwrkaxlmjj.ui.components.ChatActivityEnterView.12
            boolean processChange = false;

            @Override // android.text.TextWatcher
            public void beforeTextChanged(CharSequence charSequence, int i2, int i22, int i3) {
            }

            @Override // android.text.TextWatcher
            public void onTextChanged(CharSequence charSequence, int start, int before, int count) {
                if (ChatActivityEnterView.this.innerTextChange != 1) {
                    ChatActivityEnterView.this.checkSendButton(true);
                    CharSequence message = AndroidUtilities.getTrimmedString(charSequence.toString());
                    if (ChatActivityEnterView.this.delegate != null && !ChatActivityEnterView.this.ignoreTextChange) {
                        if (count > 2 || charSequence == null || charSequence.length() == 0) {
                            ChatActivityEnterView.this.messageWebPageSearch = true;
                        }
                        ChatActivityEnterView.this.delegate.onTextChanged(charSequence, before > count + 1 || count - before > 2);
                    }
                    if (ChatActivityEnterView.this.innerTextChange != 2 && count - before > 1) {
                        this.processChange = true;
                    }
                    if (ChatActivityEnterView.this.editingMessageObject == null && !ChatActivityEnterView.this.canWriteToChannel && message.length() != 0 && ChatActivityEnterView.this.lastTypingTimeSend < System.currentTimeMillis() - DefaultRenderersFactory.DEFAULT_ALLOWED_VIDEO_JOINING_TIME_MS && !ChatActivityEnterView.this.ignoreTextChange) {
                        int currentTime = ConnectionsManager.getInstance(ChatActivityEnterView.this.currentAccount).getCurrentTime();
                        TLRPC.User currentUser = null;
                        if (((int) ChatActivityEnterView.this.dialog_id) > 0) {
                            currentUser = ChatActivityEnterView.this.accountInstance.getMessagesController().getUser(Integer.valueOf((int) ChatActivityEnterView.this.dialog_id));
                        }
                        if (currentUser != null) {
                            if (currentUser.id != UserConfig.getInstance(ChatActivityEnterView.this.currentAccount).getClientUserId()) {
                                if (currentUser.status != null && currentUser.status.expires < currentTime && !ChatActivityEnterView.this.accountInstance.getMessagesController().onlinePrivacy.containsKey(Integer.valueOf(currentUser.id))) {
                                    return;
                                }
                            } else {
                                return;
                            }
                        }
                        ChatActivityEnterView.this.lastTypingTimeSend = System.currentTimeMillis();
                        if (ChatActivityEnterView.this.delegate != null) {
                            ChatActivityEnterView.this.delegate.needSendTyping();
                        }
                    }
                }
            }

            @Override // android.text.TextWatcher
            public void afterTextChanged(Editable editable) {
                if (ChatActivityEnterView.this.innerTextChange == 0) {
                    if (ChatActivityEnterView.this.sendByEnter && editable.length() > 0 && editable.charAt(editable.length() - 1) == '\n' && ChatActivityEnterView.this.editingMessageObject == null) {
                        ChatActivityEnterView.this.sendMessage();
                    }
                    if (this.processChange) {
                        ImageSpan[] spans = (ImageSpan[]) editable.getSpans(0, editable.length(), ImageSpan.class);
                        for (ImageSpan imageSpan : spans) {
                            editable.removeSpan(imageSpan);
                        }
                        Emoji.replaceEmoji(editable, ChatActivityEnterView.this.messageEditText.getPaint().getFontMetricsInt(), AndroidUtilities.dp(20.0f), false);
                        this.processChange = false;
                    }
                }
            }
        });
        LinearLayout linearLayout2 = new LinearLayout(context);
        this.attachLayout = linearLayout2;
        linearLayout2.setOrientation(0);
        this.attachLayout.setEnabled(false);
        this.attachLayout.setPivotX(AndroidUtilities.dp(48.0f));
        frameLayout.addView(this.attachLayout, LayoutHelper.createFrame(-2.0f, 48.0f, 85, 0.0f, 0.0f, 0.0f, 2.0f));
        if (isChat) {
            ImageView imageView = new ImageView(context);
            this.attachButton = imageView;
            imageView.setColorFilter(new PorterDuffColorFilter(Theme.getColor(Theme.key_chat_messagePanelIcons), PorterDuff.Mode.MULTIPLY));
            this.attachButton.setImageResource(R.drawable.input_attach);
            this.attachButton.setScaleType(ImageView.ScaleType.CENTER);
            frameLayout.addView(this.attachButton, LayoutHelper.createFrame(48.0f, 48.0f, 83, 3.0f, 0.0f, 0.0f, 2.0f));
            this.attachButton.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$ChatActivityEnterView$eB5w8v9lgm3IWn6DUwdTz2S2XrI
                @Override // android.view.View.OnClickListener
                public final void onClick(View view) {
                    this.f$0.lambda$new$1$ChatActivityEnterView(view);
                }
            });
            this.attachButton.setContentDescription(LocaleController.getString("AccDescrAttachButton", R.string.AccDescrAttachButton));
            if (this.parentFragment != null) {
                Drawable drawable1 = context.getResources().getDrawable(R.drawable.input_calendar1).mutate();
                Drawable drawable2 = context.getResources().getDrawable(R.drawable.input_calendar2).mutate();
                drawable1.setColorFilter(new PorterDuffColorFilter(Theme.getColor(Theme.key_chat_messagePanelIcons), PorterDuff.Mode.MULTIPLY));
                drawable2.setColorFilter(new PorterDuffColorFilter(Theme.getColor(Theme.key_chat_recordedVoiceDot), PorterDuff.Mode.MULTIPLY));
                CombinedDrawable combinedDrawable = new CombinedDrawable(drawable1, drawable2);
                ImageView imageView2 = new ImageView(context);
                this.scheduledButton = imageView2;
                imageView2.setImageDrawable(combinedDrawable);
                this.scheduledButton.setVisibility(8);
                this.scheduledButton.setContentDescription(LocaleController.getString("ScheduledMessages", R.string.ScheduledMessages));
                this.scheduledButton.setScaleType(ImageView.ScaleType.CENTER);
                frameLayout.addView(this.scheduledButton, LayoutHelper.createFrame(48, 48, 85));
                this.scheduledButton.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$ChatActivityEnterView$zBU2pXlXQPwwKQ0ueIdNKw-maj4
                    @Override // android.view.View.OnClickListener
                    public final void onClick(View view) {
                        this.f$0.lambda$new$2$ChatActivityEnterView(view);
                    }
                });
            }
            ImageView imageView3 = new ImageView(context);
            this.botButton = imageView3;
            imageView3.setColorFilter(new PorterDuffColorFilter(Theme.getColor(Theme.key_chat_messagePanelIcons), PorterDuff.Mode.MULTIPLY));
            this.botButton.setImageResource(R.drawable.input_bot2);
            this.botButton.setScaleType(ImageView.ScaleType.CENTER);
            this.botButton.setVisibility(8);
            this.attachLayout.addView(this.botButton, LayoutHelper.createLinear(48, 48));
            this.botButton.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$ChatActivityEnterView$8_R-HM0uEzL29QdzTEKG9jNmoZ0
                @Override // android.view.View.OnClickListener
                public final void onClick(View view) {
                    this.f$0.lambda$new$3$ChatActivityEnterView(view);
                }
            });
            ImageView imageView4 = new ImageView(context);
            this.notifyButton = imageView4;
            imageView4.setImageResource(this.silent ? R.drawable.input_notify_off : R.drawable.input_notify_on);
            ImageView imageView5 = this.notifyButton;
            if (this.silent) {
                i = R.string.AccDescrChanSilentOn;
                str = "AccDescrChanSilentOn";
            } else {
                i = R.string.AccDescrChanSilentOff;
                str = "AccDescrChanSilentOff";
            }
            imageView5.setContentDescription(LocaleController.getString(str, i));
            this.notifyButton.setColorFilter(new PorterDuffColorFilter(Theme.getColor(Theme.key_chat_messagePanelIcons), PorterDuff.Mode.MULTIPLY));
            this.notifyButton.setScaleType(ImageView.ScaleType.CENTER);
            this.notifyButton.setVisibility((!this.canWriteToChannel || ((chatActivityEnterViewDelegate = this.delegate) != null && chatActivityEnterViewDelegate.hasScheduledMessages())) ? 8 : 0);
            this.attachLayout.addView(this.notifyButton, LayoutHelper.createLinear(48, 48));
            this.notifyButton.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$ChatActivityEnterView$DK3KMrIdPUKfH5o8mpOxmUnvoj4
                @Override // android.view.View.OnClickListener
                public final void onClick(View view) {
                    this.f$0.lambda$new$4$ChatActivityEnterView(view);
                }
            });
        }
        FrameLayout emojiButtonContainer = new FrameLayout(context);
        this.attachLayout.addView(emojiButtonContainer, LayoutHelper.createLinear(48, 48));
        for (int a = 0; a < 2; a++) {
            this.emojiButton[a] = new ImageView(context) { // from class: im.uwrkaxlmjj.ui.components.ChatActivityEnterView.13
                @Override // android.widget.ImageView, android.view.View
                protected void onDraw(Canvas canvas) {
                    super.onDraw(canvas);
                    if (getTag() != null && ChatActivityEnterView.this.attachLayout != null && !ChatActivityEnterView.this.emojiViewVisible && !MediaDataController.getInstance(ChatActivityEnterView.this.currentAccount).getUnreadStickerSets().isEmpty() && ChatActivityEnterView.this.dotPaint != null) {
                        int x = (getWidth() / 2) + AndroidUtilities.dp(9.0f);
                        int y = (getHeight() / 2) - AndroidUtilities.dp(8.0f);
                        canvas.drawCircle(x, y, AndroidUtilities.dp(5.0f), ChatActivityEnterView.this.dotPaint);
                    }
                }
            };
            this.emojiButton[a].setColorFilter(new PorterDuffColorFilter(Theme.getColor(Theme.key_chat_messagePanelIcons), PorterDuff.Mode.MULTIPLY));
            this.emojiButton[a].setScaleType(ImageView.ScaleType.CENTER_INSIDE);
            emojiButtonContainer.addView(this.emojiButton[a], LayoutHelper.createFrame(48.0f, 48.0f, 83, 0.0f, 0.0f, 0.0f, 0.0f));
            this.emojiButton[a].setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$ChatActivityEnterView$teKHYmNzlSnJyFFS_kZYg-UxIDU
                @Override // android.view.View.OnClickListener
                public final void onClick(View view) {
                    this.f$0.lambda$new$5$ChatActivityEnterView(view);
                }
            });
            this.emojiButton[a].setContentDescription(LocaleController.getString("AccDescrEmojiButton", R.string.AccDescrEmojiButton));
            if (a == 1) {
                this.emojiButton[a].setVisibility(4);
                this.emojiButton[a].setAlpha(0.0f);
                this.emojiButton[a].setScaleX(0.1f);
                this.emojiButton[a].setScaleY(0.1f);
            }
        }
        setEmojiButtonImage(false, false);
        FrameLayout frameLayout2 = new FrameLayout(context);
        this.recordedAudioPanel = frameLayout2;
        frameLayout2.setVisibility(this.audioToSend == null ? 8 : 0);
        this.recordedAudioPanel.setBackgroundColor(Theme.getColor(Theme.key_chat_messagePanelBackground));
        this.recordedAudioPanel.setFocusable(true);
        this.recordedAudioPanel.setFocusableInTouchMode(true);
        this.recordedAudioPanel.setClickable(true);
        frameLayout.addView(this.recordedAudioPanel, LayoutHelper.createFrame(-1, 48, 80));
        ImageView imageView6 = new ImageView(context);
        this.recordDeleteImageView = imageView6;
        imageView6.setScaleType(ImageView.ScaleType.CENTER);
        this.recordDeleteImageView.setImageResource(R.drawable.msg_delete);
        this.recordDeleteImageView.setColorFilter(new PorterDuffColorFilter(Theme.getColor(Theme.key_chat_messagePanelVoiceDelete), PorterDuff.Mode.MULTIPLY));
        this.recordDeleteImageView.setContentDescription(LocaleController.getString("Delete", R.string.Delete));
        this.recordedAudioPanel.addView(this.recordDeleteImageView, LayoutHelper.createFrame(48, 48.0f));
        this.recordDeleteImageView.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$ChatActivityEnterView$DbbLo_-9ks_IpGbbD-2mM1kXTwg
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                this.f$0.lambda$new$6$ChatActivityEnterView(view);
            }
        });
        VideoTimelineView videoTimelineView = new VideoTimelineView(context);
        this.videoTimelineView = videoTimelineView;
        videoTimelineView.setColor(Theme.getColor(Theme.key_chat_messagePanelVideoFrame));
        this.videoTimelineView.setRoundFrames(true);
        this.videoTimelineView.setDelegate(new VideoTimelineView.VideoTimelineViewDelegate() { // from class: im.uwrkaxlmjj.ui.components.ChatActivityEnterView.14
            @Override // im.uwrkaxlmjj.ui.components.VideoTimelineView.VideoTimelineViewDelegate
            public void onLeftProgressChanged(float progress) {
                if (ChatActivityEnterView.this.videoToSendMessageObject != null) {
                    ChatActivityEnterView.this.videoToSendMessageObject.startTime = (long) (ChatActivityEnterView.this.videoToSendMessageObject.estimatedDuration * progress);
                    ChatActivityEnterView.this.delegate.needChangeVideoPreviewState(2, progress);
                }
            }

            @Override // im.uwrkaxlmjj.ui.components.VideoTimelineView.VideoTimelineViewDelegate
            public void onRightProgressChanged(float progress) {
                if (ChatActivityEnterView.this.videoToSendMessageObject != null) {
                    ChatActivityEnterView.this.videoToSendMessageObject.endTime = (long) (ChatActivityEnterView.this.videoToSendMessageObject.estimatedDuration * progress);
                    ChatActivityEnterView.this.delegate.needChangeVideoPreviewState(2, progress);
                }
            }

            @Override // im.uwrkaxlmjj.ui.components.VideoTimelineView.VideoTimelineViewDelegate
            public void didStartDragging() {
                ChatActivityEnterView.this.delegate.needChangeVideoPreviewState(1, 0.0f);
            }

            @Override // im.uwrkaxlmjj.ui.components.VideoTimelineView.VideoTimelineViewDelegate
            public void didStopDragging() {
                ChatActivityEnterView.this.delegate.needChangeVideoPreviewState(0, 0.0f);
            }
        });
        this.recordedAudioPanel.addView(this.videoTimelineView, LayoutHelper.createFrame(-1.0f, 32.0f, 19, 40.0f, 0.0f, 0.0f, 0.0f));
        View view = new View(context);
        this.recordedAudioBackground = view;
        view.setBackgroundDrawable(Theme.createRoundRectDrawable(AndroidUtilities.dp(18.0f), Theme.getColor(Theme.key_chat_recordedVoiceBackground)));
        this.recordedAudioPanel.addView(this.recordedAudioBackground, LayoutHelper.createFrame(-1.0f, 36.0f, 19, 48.0f, 0.0f, 0.0f, 0.0f));
        SeekBarWaveformView seekBarWaveformView = new SeekBarWaveformView(context);
        this.recordedAudioSeekBar = seekBarWaveformView;
        this.recordedAudioPanel.addView(seekBarWaveformView, LayoutHelper.createFrame(-1.0f, 32.0f, 19, 92.0f, 0.0f, 52.0f, 0.0f));
        this.playDrawable = Theme.createSimpleSelectorDrawable(context, R.drawable.s_play, Theme.getColor(Theme.key_chat_recordedVoicePlayPause), Theme.getColor(Theme.key_chat_recordedVoicePlayPausePressed));
        this.pauseDrawable = Theme.createSimpleSelectorDrawable(context, R.drawable.s_pause, Theme.getColor(Theme.key_chat_recordedVoicePlayPause), Theme.getColor(Theme.key_chat_recordedVoicePlayPausePressed));
        ImageView imageView7 = new ImageView(context);
        this.recordedAudioPlayButton = imageView7;
        imageView7.setImageDrawable(this.playDrawable);
        this.recordedAudioPlayButton.setScaleType(ImageView.ScaleType.CENTER);
        this.recordedAudioPlayButton.setContentDescription(LocaleController.getString("AccActionPlay", R.string.AccActionPlay));
        this.recordedAudioPanel.addView(this.recordedAudioPlayButton, LayoutHelper.createFrame(48.0f, 48.0f, 83, 48.0f, 0.0f, 0.0f, 0.0f));
        this.recordedAudioPlayButton.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$ChatActivityEnterView$9ByKIwsDSRTobmUdaB3C1XW-vFM
            @Override // android.view.View.OnClickListener
            public final void onClick(View view2) {
                this.f$0.lambda$new$7$ChatActivityEnterView(view2);
            }
        });
        TextView textView = new TextView(context);
        this.recordedAudioTimeTextView = textView;
        textView.setTextColor(Theme.getColor(Theme.key_chat_messagePanelVoiceDuration));
        this.recordedAudioTimeTextView.setTextSize(1, 13.0f);
        this.recordedAudioPanel.addView(this.recordedAudioTimeTextView, LayoutHelper.createFrame(-2.0f, -2.0f, 21, 0.0f, 0.0f, 13.0f, 0.0f));
        FrameLayout frameLayout3 = new FrameLayout(context);
        this.recordPanel = frameLayout3;
        frameLayout3.setVisibility(8);
        this.recordPanel.setBackgroundColor(Theme.getColor(Theme.key_chat_messagePanelBackground));
        frameLayout.addView(this.recordPanel, LayoutHelper.createFrame(-1, 48, 80));
        this.recordPanel.setOnTouchListener(new View.OnTouchListener() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$ChatActivityEnterView$p7OqqNcvoZPwy63NrDtVThwBdhc
            @Override // android.view.View.OnTouchListener
            public final boolean onTouch(View view2, MotionEvent motionEvent) {
                return ChatActivityEnterView.lambda$new$8(view2, motionEvent);
            }
        });
        LinearLayout linearLayout3 = new LinearLayout(context);
        this.slideText = linearLayout3;
        linearLayout3.setOrientation(0);
        this.recordPanel.addView(this.slideText, LayoutHelper.createFrame(-2.0f, -2.0f, 17, 30.0f, 0.0f, 0.0f, 0.0f));
        ImageView imageView8 = new ImageView(context);
        this.recordCancelImage = imageView8;
        imageView8.setImageResource(R.drawable.slidearrow);
        this.recordCancelImage.setColorFilter(new PorterDuffColorFilter(Theme.getColor(Theme.key_chat_recordVoiceCancel), PorterDuff.Mode.MULTIPLY));
        this.slideText.addView(this.recordCancelImage, LayoutHelper.createLinear(-2, -2, 16, 0, 1, 0, 0));
        TextView textView2 = new TextView(context);
        this.recordCancelText = textView2;
        textView2.setText(LocaleController.getString("SlideToCancel", R.string.SlideToCancel));
        this.recordCancelText.setTextColor(Theme.getColor(Theme.key_chat_recordVoiceCancel));
        this.recordCancelText.setTextSize(1, 12.0f);
        this.slideText.addView(this.recordCancelText, LayoutHelper.createLinear(-2, -2, 16, 6, 0, 0, 0));
        TextView textView3 = new TextView(context);
        this.recordSendText = textView3;
        textView3.setText(LocaleController.getString("Cancel", R.string.Cancel).toUpperCase());
        this.recordSendText.setTextColor(Theme.getColor(Theme.key_chat_fieldOverlayText));
        this.recordSendText.setTextSize(1, 16.0f);
        this.recordSendText.setGravity(17);
        this.recordSendText.setTypeface(AndroidUtilities.getTypeface("fonts/rmedium.ttf"));
        this.recordSendText.setAlpha(0.0f);
        this.recordSendText.setPadding(AndroidUtilities.dp(36.0f), 0, 0, 0);
        this.recordSendText.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$ChatActivityEnterView$G9jTPx_hrmMc3iw70DQvnTRf58Y
            @Override // android.view.View.OnClickListener
            public final void onClick(View view2) {
                this.f$0.lambda$new$9$ChatActivityEnterView(view2);
            }
        });
        this.recordPanel.addView(this.recordSendText, LayoutHelper.createFrame(-2.0f, -1.0f, 49, 0.0f, 0.0f, 0.0f, 0.0f));
        LinearLayout linearLayout4 = new LinearLayout(context);
        this.recordTimeContainer = linearLayout4;
        linearLayout4.setOrientation(0);
        this.recordTimeContainer.setPadding(AndroidUtilities.dp(13.0f), 0, 0, 0);
        this.recordTimeContainer.setBackgroundColor(Theme.getColor(Theme.key_chat_messagePanelBackground));
        this.recordPanel.addView(this.recordTimeContainer, LayoutHelper.createFrame(-2, -2, 16));
        RecordDot recordDot = new RecordDot(context);
        this.recordDot = recordDot;
        this.recordTimeContainer.addView(recordDot, LayoutHelper.createLinear(11, 11, 16, 0, 1, 0, 0));
        TextView textView4 = new TextView(context);
        this.recordTimeText = textView4;
        textView4.setTextColor(Theme.getColor(Theme.key_chat_recordTime));
        this.recordTimeText.setTextSize(1, 16.0f);
        this.recordTimeContainer.addView(this.recordTimeText, LayoutHelper.createLinear(-2, -2, 16, 6, 0, 0, 0));
        FrameLayout frameLayout4 = new FrameLayout(context);
        this.sendButtonContainer = frameLayout4;
        frameLayout4.setClipChildren(false);
        this.sendButtonContainer.setClipToPadding(false);
        this.textFieldContainer.addView(this.sendButtonContainer, LayoutHelper.createLinear(48.0f, 48.0f, 80, 0.0f, 0.0f, 0.0f, 2.0f));
        FrameLayout frameLayout5 = new FrameLayout(context);
        this.audioVideoButtonContainer = frameLayout5;
        frameLayout5.setBackgroundColor(Theme.getColor(Theme.key_chat_messagePanelBackground));
        this.audioVideoButtonContainer.setSoundEffectsEnabled(false);
        this.sendButtonContainer.addView(this.audioVideoButtonContainer, LayoutHelper.createFrame(48, 48.0f));
        this.audioVideoButtonContainer.setOnTouchListener(new View.OnTouchListener() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$ChatActivityEnterView$7ER_OxVcc0cZVy0_Dr4FEKne5rs
            @Override // android.view.View.OnTouchListener
            public final boolean onTouch(View view2, MotionEvent motionEvent) {
                return this.f$0.lambda$new$14$ChatActivityEnterView(view2, motionEvent);
            }
        });
        ImageView imageView9 = new ImageView(context);
        this.audioSendButton = imageView9;
        imageView9.setScaleType(ImageView.ScaleType.CENTER_INSIDE);
        this.audioSendButton.setColorFilter(new PorterDuffColorFilter(Theme.getColor(Theme.key_chat_messagePanelIcons), PorterDuff.Mode.MULTIPLY));
        this.audioSendButton.setImageResource(R.drawable.input_mic);
        this.audioSendButton.setPadding(0, 0, AndroidUtilities.dp(4.0f), 0);
        this.audioSendButton.setContentDescription(LocaleController.getString("AccDescrVoiceMessage", R.string.AccDescrVoiceMessage));
        this.audioSendButton.setFocusable(true);
        this.audioSendButton.setAccessibilityDelegate(this.mediaMessageButtonsDelegate);
        this.audioVideoButtonContainer.addView(this.audioSendButton, LayoutHelper.createFrame(48, 48.0f));
        if (isChat) {
            ImageView imageView10 = new ImageView(context);
            this.videoSendButton = imageView10;
            imageView10.setScaleType(ImageView.ScaleType.CENTER_INSIDE);
            this.videoSendButton.setColorFilter(new PorterDuffColorFilter(Theme.getColor(Theme.key_chat_messagePanelIcons), PorterDuff.Mode.MULTIPLY));
            this.videoSendButton.setImageResource(R.drawable.input_video);
            this.videoSendButton.setPadding(0, 0, AndroidUtilities.dp(4.0f), 0);
            this.videoSendButton.setContentDescription(LocaleController.getString("AccDescrVideoMessage", R.string.AccDescrVideoMessage));
            this.videoSendButton.setFocusable(true);
            this.videoSendButton.setAccessibilityDelegate(this.mediaMessageButtonsDelegate);
            this.audioVideoButtonContainer.addView(this.videoSendButton, LayoutHelper.createFrame(48, 48.0f));
        }
        RecordCircle recordCircle = new RecordCircle(context);
        this.recordCircle = recordCircle;
        recordCircle.setVisibility(8);
        this.sizeNotifierLayout.addView(this.recordCircle, LayoutHelper.createFrame(124.0f, 194.0f, 85, 0.0f, 0.0f, -36.0f, 0.0f));
        ImageView imageView11 = new ImageView(context);
        this.cancelBotButton = imageView11;
        imageView11.setVisibility(4);
        this.cancelBotButton.setScaleType(ImageView.ScaleType.CENTER_INSIDE);
        ImageView imageView12 = this.cancelBotButton;
        CloseProgressDrawable2 closeProgressDrawable2 = new CloseProgressDrawable2();
        this.progressDrawable = closeProgressDrawable2;
        imageView12.setImageDrawable(closeProgressDrawable2);
        this.cancelBotButton.setContentDescription(LocaleController.getString("Cancel", R.string.Cancel));
        this.progressDrawable.setColorFilter(new PorterDuffColorFilter(Theme.getColor(Theme.key_chat_messagePanelCancelInlineBot), PorterDuff.Mode.MULTIPLY));
        this.cancelBotButton.setSoundEffectsEnabled(false);
        this.cancelBotButton.setScaleX(0.1f);
        this.cancelBotButton.setScaleY(0.1f);
        this.cancelBotButton.setAlpha(0.0f);
        this.sendButtonContainer.addView(this.cancelBotButton, LayoutHelper.createFrame(48, 48.0f));
        this.cancelBotButton.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$ChatActivityEnterView$8R0ef6V0M6ckyPeL___CljxFJ-4
            @Override // android.view.View.OnClickListener
            public final void onClick(View view2) {
                this.f$0.lambda$new$15$ChatActivityEnterView(view2);
            }
        });
        if (isInScheduleMode()) {
            this.sendButtonDrawable = context.getResources().getDrawable(R.drawable.input_schedule).mutate();
            this.sendButtonInverseDrawable = context.getResources().getDrawable(R.drawable.input_schedule).mutate();
            this.inactinveSendButtonDrawable = context.getResources().getDrawable(R.drawable.input_schedule).mutate();
        } else {
            this.sendButtonDrawable = context.getResources().getDrawable(R.drawable.ic_send).mutate();
            this.sendButtonInverseDrawable = context.getResources().getDrawable(R.drawable.ic_send).mutate();
            this.inactinveSendButtonDrawable = context.getResources().getDrawable(R.drawable.ic_send).mutate();
        }
        View view2 = new View(context) { // from class: im.uwrkaxlmjj.ui.components.ChatActivityEnterView.15
            private float animateBounce;
            private float animationDuration;
            private float animationProgress;
            private int drawableColor;
            private long lastAnimationTime;

            @Override // android.view.View
            protected void onDraw(Canvas canvas) {
                int color;
                int x = (getMeasuredWidth() - ChatActivityEnterView.this.sendButtonDrawable.getIntrinsicWidth()) / 2;
                int y = (getMeasuredHeight() - ChatActivityEnterView.this.sendButtonDrawable.getIntrinsicHeight()) / 2;
                if (ChatActivityEnterView.this.isInScheduleMode()) {
                    y -= AndroidUtilities.dp(1.0f);
                } else {
                    x += AndroidUtilities.dp(2.0f);
                }
                boolean z = ChatActivityEnterView.this.sendPopupWindow != null && ChatActivityEnterView.this.sendPopupWindow.isShowing();
                boolean showingPopup = z;
                if (z) {
                    color = Theme.getColor(Theme.key_chat_messagePanelVoicePressed);
                } else {
                    color = Theme.getColor(Theme.key_chat_messagePanelSend);
                }
                if (color != this.drawableColor) {
                    this.lastAnimationTime = SystemClock.uptimeMillis();
                    if (showingPopup) {
                        this.animationProgress = 0.0f;
                        this.animationDuration = 200.0f;
                    } else if (this.drawableColor != 0) {
                        this.animationProgress = 0.0f;
                        this.animationDuration = 120.0f;
                    } else {
                        this.animationProgress = 1.0f;
                    }
                    this.drawableColor = color;
                    ChatActivityEnterView.this.sendButtonDrawable.setColorFilter(new PorterDuffColorFilter(Theme.getColor(Theme.key_chat_messagePanelSend), PorterDuff.Mode.MULTIPLY));
                    int c = Theme.getColor(Theme.key_chat_messagePanelIcons);
                    ChatActivityEnterView.this.inactinveSendButtonDrawable.setColorFilter(new PorterDuffColorFilter(Color.argb(JavaScreenCapturer.DEGREE_180, Color.red(c), Color.green(c), Color.blue(c)), PorterDuff.Mode.MULTIPLY));
                    ChatActivityEnterView.this.sendButtonInverseDrawable.setColorFilter(new PorterDuffColorFilter(Theme.getColor(Theme.key_chat_messagePanelVoicePressed), PorterDuff.Mode.MULTIPLY));
                }
                if (this.animationProgress < 1.0f) {
                    long newTime = SystemClock.uptimeMillis();
                    long dt = newTime - this.lastAnimationTime;
                    float f = this.animationProgress + (dt / this.animationDuration);
                    this.animationProgress = f;
                    if (f > 1.0f) {
                        this.animationProgress = 1.0f;
                    }
                    this.lastAnimationTime = newTime;
                    invalidate();
                }
                if (!showingPopup) {
                    if (ChatActivityEnterView.this.slowModeTimer != Integer.MAX_VALUE || ChatActivityEnterView.this.isInScheduleMode()) {
                        ChatActivityEnterView.this.sendButtonDrawable.setBounds(x, y, ChatActivityEnterView.this.sendButtonDrawable.getIntrinsicWidth() + x, ChatActivityEnterView.this.sendButtonDrawable.getIntrinsicHeight() + y);
                        ChatActivityEnterView.this.sendButtonDrawable.draw(canvas);
                    } else {
                        ChatActivityEnterView.this.inactinveSendButtonDrawable.setBounds(x, y, ChatActivityEnterView.this.sendButtonDrawable.getIntrinsicWidth() + x, ChatActivityEnterView.this.sendButtonDrawable.getIntrinsicHeight() + y);
                        ChatActivityEnterView.this.inactinveSendButtonDrawable.draw(canvas);
                    }
                }
                if (showingPopup || this.animationProgress != 1.0f) {
                    Theme.dialogs_onlineCirclePaint.setColor(Theme.getColor(Theme.key_chat_messagePanelSend));
                    int rad = AndroidUtilities.dp(20.0f);
                    if (showingPopup) {
                        ChatActivityEnterView.this.sendButtonInverseDrawable.setAlpha(255);
                        float p = this.animationProgress;
                        if (p <= 0.25f) {
                            float progress = p / 0.25f;
                            rad = (int) (rad + (AndroidUtilities.dp(2.0f) * CubicBezierInterpolator.EASE_IN.getInterpolation(progress)));
                        } else {
                            float p2 = p - 0.25f;
                            if (p2 <= 0.5f) {
                                float progress2 = p2 / 0.5f;
                                rad = (int) (rad + (AndroidUtilities.dp(2.0f) - (AndroidUtilities.dp(3.0f) * CubicBezierInterpolator.EASE_IN.getInterpolation(progress2))));
                            } else {
                                float progress3 = (p2 - 0.5f) / 0.25f;
                                rad = (int) (rad + (-AndroidUtilities.dp(1.0f)) + (AndroidUtilities.dp(1.0f) * CubicBezierInterpolator.EASE_IN.getInterpolation(progress3)));
                            }
                        }
                    } else {
                        int alpha = (int) ((1.0f - this.animationProgress) * 255.0f);
                        Theme.dialogs_onlineCirclePaint.setAlpha(alpha);
                        ChatActivityEnterView.this.sendButtonInverseDrawable.setAlpha(alpha);
                    }
                    canvas.drawCircle(getMeasuredWidth() / 2, getMeasuredHeight() / 2, rad, Theme.dialogs_onlineCirclePaint);
                    ChatActivityEnterView.this.sendButtonInverseDrawable.setBounds(x, y, ChatActivityEnterView.this.sendButtonDrawable.getIntrinsicWidth() + x, ChatActivityEnterView.this.sendButtonDrawable.getIntrinsicHeight() + y);
                    ChatActivityEnterView.this.sendButtonInverseDrawable.draw(canvas);
                }
            }
        };
        this.sendButton = view2;
        view2.setVisibility(4);
        int color = Theme.getColor(Theme.key_chat_messagePanelSend);
        this.sendButton.setContentDescription(LocaleController.getString("Send", R.string.Send));
        this.sendButton.setSoundEffectsEnabled(false);
        this.sendButton.setScaleX(0.1f);
        this.sendButton.setScaleY(0.1f);
        this.sendButton.setAlpha(0.0f);
        if (Build.VERSION.SDK_INT >= 21) {
            this.sendButton.setBackgroundDrawable(Theme.createSelectorDrawable(Color.argb(24, Color.red(color), Color.green(color), Color.blue(color)), 1));
        }
        this.sendButtonContainer.addView(this.sendButton, LayoutHelper.createFrame(48.0f, 48.0f, 80, 0.0f, 0.0f, 0.0f, -2.0f));
        this.sendButton.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$ChatActivityEnterView$3-HN7xk2VCA5CHNZjG5Yw2TevHg
            @Override // android.view.View.OnClickListener
            public final void onClick(View view3) {
                this.f$0.lambda$new$16$ChatActivityEnterView(view3);
            }
        });
        SimpleTextView simpleTextView = new SimpleTextView(context);
        this.slowModeButton = simpleTextView;
        simpleTextView.setTextSize(18);
        this.slowModeButton.setVisibility(4);
        this.slowModeButton.setSoundEffectsEnabled(false);
        this.slowModeButton.setScaleX(0.1f);
        this.slowModeButton.setScaleY(0.1f);
        this.slowModeButton.setAlpha(0.0f);
        this.slowModeButton.setPadding(0, 0, AndroidUtilities.dp(13.0f), 0);
        this.slowModeButton.setGravity(21);
        this.slowModeButton.setTextColor(Theme.getColor(Theme.key_chat_messagePanelIcons));
        this.sendButtonContainer.addView(this.slowModeButton, LayoutHelper.createFrame(64, 48, 53));
        this.slowModeButton.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$ChatActivityEnterView$HQ6NlrOsxSjygh5nYSZbrmfKQt0
            @Override // android.view.View.OnClickListener
            public final void onClick(View view3) {
                this.f$0.lambda$new$17$ChatActivityEnterView(view3);
            }
        });
        ImageView imageView13 = new ImageView(context);
        this.expandStickersButton = imageView13;
        imageView13.setPadding(0, 0, AndroidUtilities.dp(4.0f), 0);
        this.expandStickersButton.setScaleType(ImageView.ScaleType.CENTER);
        ImageView imageView14 = this.expandStickersButton;
        AnimatedArrowDrawable animatedArrowDrawable = new AnimatedArrowDrawable(Theme.getColor(Theme.key_chat_messagePanelIcons), false);
        this.stickersArrow = animatedArrowDrawable;
        imageView14.setImageDrawable(animatedArrowDrawable);
        this.expandStickersButton.setVisibility(8);
        this.expandStickersButton.setScaleX(0.1f);
        this.expandStickersButton.setScaleY(0.1f);
        this.expandStickersButton.setAlpha(0.0f);
        this.sendButtonContainer.addView(this.expandStickersButton, LayoutHelper.createFrame(48, 48.0f));
        this.expandStickersButton.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$ChatActivityEnterView$V-D_PRyQoxEoMI_Efug_JROd7_M
            @Override // android.view.View.OnClickListener
            public final void onClick(View view3) {
                this.f$0.lambda$new$18$ChatActivityEnterView(view3);
            }
        });
        this.expandStickersButton.setContentDescription(LocaleController.getString("AccDescrExpandPanel", R.string.AccDescrExpandPanel));
        FrameLayout frameLayout6 = new FrameLayout(context);
        this.doneButtonContainer = frameLayout6;
        frameLayout6.setVisibility(8);
        this.textFieldContainer.addView(this.doneButtonContainer, LayoutHelper.createLinear(48, 48, 80));
        this.doneButtonContainer.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$ChatActivityEnterView$M3W1sl8puVLjpagUIFkK7JU_wu4
            @Override // android.view.View.OnClickListener
            public final void onClick(View view3) {
                this.f$0.lambda$new$19$ChatActivityEnterView(view3);
            }
        });
        Drawable drawable = Theme.createCircleDrawable(AndroidUtilities.dp(16.0f), Theme.getColor(Theme.key_chat_messagePanelSend));
        Drawable checkDrawable = context.getResources().getDrawable(R.drawable.input_done).mutate();
        checkDrawable.setColorFilter(new PorterDuffColorFilter(Theme.getColor(Theme.key_chat_messagePanelVoicePressed), PorterDuff.Mode.MULTIPLY));
        CombinedDrawable combinedDrawable2 = new CombinedDrawable(drawable, checkDrawable, 0, AndroidUtilities.dp(1.0f));
        combinedDrawable2.setCustomSize(AndroidUtilities.dp(32.0f), AndroidUtilities.dp(32.0f));
        ImageView imageView15 = new ImageView(context);
        this.doneButtonImage = imageView15;
        imageView15.setScaleType(ImageView.ScaleType.CENTER);
        this.doneButtonImage.setImageDrawable(combinedDrawable2);
        this.doneButtonImage.setContentDescription(LocaleController.getString("Done", R.string.Done));
        this.doneButtonContainer.addView(this.doneButtonImage, LayoutHelper.createFrame(48, 48.0f));
        ContextProgressView contextProgressView = new ContextProgressView(context, 0);
        this.doneButtonProgress = contextProgressView;
        contextProgressView.setVisibility(4);
        this.doneButtonContainer.addView(this.doneButtonProgress, LayoutHelper.createFrame(-1, -1.0f));
        SharedPreferences sharedPreferences = MessagesController.getGlobalEmojiSettings();
        this.keyboardHeight = sharedPreferences.getInt("kbd_height", AndroidUtilities.dp(236.0f));
        this.keyboardHeightLand = sharedPreferences.getInt("kbd_height_land3", AndroidUtilities.dp(236.0f));
        setRecordVideoButtonVisible(false, false);
        checkSendButton(false);
        checkChannelRights();
        View bottomDivider = new View(context) { // from class: im.uwrkaxlmjj.ui.components.ChatActivityEnterView.16
            @Override // android.view.View
            protected void onDraw(Canvas canvas) {
                int width = getWidth();
                int height = getHeight();
                canvas.drawLine(0.0f, height - 1, width, height - 1, Theme.dividerPaint);
            }
        };
        addView(bottomDivider, LayoutHelper.createFrame(-1.0f, 0.5f, 80));
    }

    /* JADX INFO: renamed from: im.uwrkaxlmjj.ui.components.ChatActivityEnterView$9, reason: invalid class name */
    class AnonymousClass9 extends EditTextCaption {
        AnonymousClass9(Context context) {
            super(context);
        }

        /* JADX INFO: Access modifiers changed from: private */
        /* JADX INFO: renamed from: send, reason: merged with bridge method [inline-methods] */
        public void lambda$null$0$ChatActivityEnterView$9(InputContentInfoCompat inputContentInfo, boolean notify, int scheduleDate) {
            ClipDescription description = inputContentInfo.getDescription();
            if (description.hasMimeType("image/gif")) {
                SendMessagesHelper.prepareSendingDocument(ChatActivityEnterView.this.accountInstance, null, null, inputContentInfo.getContentUri(), null, "image/gif", ChatActivityEnterView.this.dialog_id, ChatActivityEnterView.this.replyingMessageObject, inputContentInfo, null, notify, 0);
            } else {
                SendMessagesHelper.prepareSendingPhoto(ChatActivityEnterView.this.accountInstance, null, inputContentInfo.getContentUri(), ChatActivityEnterView.this.dialog_id, ChatActivityEnterView.this.replyingMessageObject, null, null, null, inputContentInfo, 0, null, notify, 0);
            }
            if (ChatActivityEnterView.this.delegate != null) {
                ChatActivityEnterView.this.delegate.onMessageSend(null, true, scheduleDate);
            }
        }

        @Override // im.uwrkaxlmjj.ui.components.EditTextCaption, androidx.appcompat.widget.AppCompatEditText, android.widget.TextView, android.view.View
        public InputConnection onCreateInputConnection(EditorInfo editorInfo) {
            InputConnection ic = super.onCreateInputConnection(editorInfo);
            try {
                EditorInfoCompat.setContentMimeTypes(editorInfo, new String[]{"image/gif", "image/*", "image/jpg", "image/png"});
                InputConnectionCompat.OnCommitContentListener callback = new InputConnectionCompat.OnCommitContentListener() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$ChatActivityEnterView$9$3P2fqw2gkiI0ngap3_OYL9l4uyM
                    @Override // androidx.core.view.inputmethod.InputConnectionCompat.OnCommitContentListener
                    public final boolean onCommitContent(InputContentInfoCompat inputContentInfoCompat, int i, Bundle bundle) {
                        return this.f$0.lambda$onCreateInputConnection$1$ChatActivityEnterView$9(inputContentInfoCompat, i, bundle);
                    }
                };
                return InputConnectionCompat.createWrapper(ic, editorInfo, callback);
            } catch (Throwable e) {
                FileLog.e(e);
                return ic;
            }
        }

        public /* synthetic */ boolean lambda$onCreateInputConnection$1$ChatActivityEnterView$9(final InputContentInfoCompat inputContentInfo, int flags, Bundle opts) {
            if (BuildCompat.isAtLeastNMR1() && (flags & 1) != 0) {
                try {
                    inputContentInfo.requestPermission();
                } catch (Exception e) {
                    return false;
                }
            }
            if (ChatActivityEnterView.this.isInScheduleMode()) {
                AlertsCreator.createScheduleDatePickerDialog(ChatActivityEnterView.this.parentActivity, UserObject.isUserSelf(ChatActivityEnterView.this.parentFragment.getCurrentUser()), new AlertsCreator.ScheduleDatePickerDelegate() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$ChatActivityEnterView$9$f4cW7eAsK8McFx_JFbDjTq7PUzs
                    @Override // im.uwrkaxlmjj.ui.components.AlertsCreator.ScheduleDatePickerDelegate
                    public final void didSelectDate(boolean z, int i) {
                        this.f$0.lambda$null$0$ChatActivityEnterView$9(inputContentInfo, z, i);
                    }
                });
            } else {
                lambda$null$0$ChatActivityEnterView$9(inputContentInfo, true, 0);
            }
            return true;
        }

        @Override // android.widget.TextView, android.view.View
        public boolean onTouchEvent(MotionEvent event) {
            if (ChatActivityEnterView.this.isPopupShowing() && event.getAction() == 0) {
                if (ChatActivityEnterView.this.searchingType != 0) {
                    ChatActivityEnterView.this.searchingType = 0;
                    ChatActivityEnterView.this.emojiView.closeSearch(false);
                }
                ChatActivityEnterView.this.showPopup(AndroidUtilities.usingHardwareInput ? 0 : 2, 0);
                ChatActivityEnterView.this.openKeyboardInternal();
            }
            try {
                return super.onTouchEvent(event);
            } catch (Exception e) {
                FileLog.e(e);
                return false;
            }
        }

        @Override // android.widget.TextView
        protected void onSelectionChanged(int selStart, int selEnd) {
            super.onSelectionChanged(selStart, selEnd);
            if (ChatActivityEnterView.this.delegate != null) {
                ChatActivityEnterView.this.delegate.onTextSelectionChanged(selStart, selEnd);
            }
        }
    }

    public /* synthetic */ void lambda$new$0$ChatActivityEnterView() {
        ChatActivityEnterViewDelegate chatActivityEnterViewDelegate = this.delegate;
        if (chatActivityEnterViewDelegate != null) {
            chatActivityEnterViewDelegate.onTextSpansChanged(this.messageEditText.getText());
        }
    }

    public /* synthetic */ void lambda$new$1$ChatActivityEnterView(View v) {
        showPopup(3, 3);
    }

    public /* synthetic */ void lambda$new$2$ChatActivityEnterView(View v) {
        ChatActivityEnterViewDelegate chatActivityEnterViewDelegate = this.delegate;
        if (chatActivityEnterViewDelegate != null) {
            chatActivityEnterViewDelegate.openScheduledMessages();
        }
    }

    public /* synthetic */ void lambda$new$3$ChatActivityEnterView(View v) {
        int i;
        if (this.searchingType != 0) {
            this.searchingType = 0;
            this.emojiView.closeSearch(false);
            this.messageEditText.requestFocus();
        }
        if (this.botReplyMarkup != null) {
            if (!isPopupShowing() || (i = this.currentPopupContentType) != 1) {
                showPopup(1, 1);
                SharedPreferences preferences1 = MessagesController.getMainSettings(this.currentAccount);
                preferences1.edit().remove("hidekeyboard_" + this.dialog_id).commit();
            } else {
                if (i == 1 && this.botButtonsMessageObject != null) {
                    SharedPreferences preferences12 = MessagesController.getMainSettings(this.currentAccount);
                    preferences12.edit().putInt("hidekeyboard_" + this.dialog_id, this.botButtonsMessageObject.getId()).commit();
                }
                openKeyboardInternal();
            }
        } else if (this.hasBotCommands) {
            setFieldText("/");
            this.messageEditText.requestFocus();
            openKeyboard();
        }
        if (this.stickersExpanded) {
            setStickersExpanded(false, false, false);
        }
    }

    public /* synthetic */ void lambda$new$4$ChatActivityEnterView(View v) {
        int i;
        String str;
        boolean z = !this.silent;
        this.silent = z;
        this.notifyButton.setImageResource(z ? R.drawable.input_notify_off : R.drawable.input_notify_on);
        MessagesController.getNotificationsSettings(this.currentAccount).edit().putBoolean("silent_" + this.dialog_id, this.silent).commit();
        NotificationsController.getInstance(this.currentAccount).updateServerNotificationsSettings(this.dialog_id);
        if (this.silent) {
            ToastUtils.show(R.string.ChannelNotifyMembersInfoOff);
        } else {
            ToastUtils.show(R.string.ChannelNotifyMembersInfoOn);
        }
        ImageView imageView = this.notifyButton;
        if (this.silent) {
            i = R.string.AccDescrChanSilentOn;
            str = "AccDescrChanSilentOn";
        } else {
            i = R.string.AccDescrChanSilentOff;
            str = "AccDescrChanSilentOff";
        }
        imageView.setContentDescription(LocaleController.getString(str, i));
        updateFieldHint();
    }

    public /* synthetic */ void lambda$new$5$ChatActivityEnterView(View view) {
        if (!isPopupShowing() || this.currentPopupContentType != 0) {
            showPopup(1, 0);
            this.emojiView.onOpen(this.messageEditText.length() > 0);
            return;
        }
        if (this.searchingType != 0) {
            this.searchingType = 0;
            this.emojiView.closeSearch(false);
            this.messageEditText.requestFocus();
        }
        openKeyboardInternal();
    }

    public /* synthetic */ void lambda$new$6$ChatActivityEnterView(View v) {
        if (this.videoToSendMessageObject != null) {
            CameraController.getInstance().cancelOnInitRunnable(this.onFinishInitCameraRunnable);
            this.delegate.needStartRecordVideo(2, true, 0);
        } else {
            MessageObject playing = MediaController.getInstance().getPlayingMessageObject();
            if (playing != null && playing == this.audioToSendMessageObject) {
                MediaController.getInstance().cleanupPlayer(true, true);
            }
        }
        if (this.audioToSendPath != null) {
            new File(this.audioToSendPath).delete();
        }
        hideRecordedAudioPanel();
        checkSendButton(true);
    }

    public /* synthetic */ void lambda$new$7$ChatActivityEnterView(View v) {
        if (this.audioToSend == null) {
            return;
        }
        if (MediaController.getInstance().isPlayingMessage(this.audioToSendMessageObject) && !MediaController.getInstance().isMessagePaused()) {
            MediaController.getInstance().lambda$startAudioAgain$5$MediaController(this.audioToSendMessageObject);
            this.recordedAudioPlayButton.setImageDrawable(this.playDrawable);
            this.recordedAudioPlayButton.setContentDescription(LocaleController.getString("AccActionPlay", R.string.AccActionPlay));
        } else {
            this.recordedAudioPlayButton.setImageDrawable(this.pauseDrawable);
            MediaController.getInstance().playMessage(this.audioToSendMessageObject);
            this.recordedAudioPlayButton.setContentDescription(LocaleController.getString("AccActionPause", R.string.AccActionPause));
        }
    }

    static /* synthetic */ boolean lambda$new$8(View v, MotionEvent event) {
        return true;
    }

    public /* synthetic */ void lambda$new$9$ChatActivityEnterView(View v) {
        if (this.hasRecordVideo && this.videoSendButton.getTag() != null) {
            CameraController.getInstance().cancelOnInitRunnable(this.onFinishInitCameraRunnable);
            this.delegate.needStartRecordVideo(2, true, 0);
        } else {
            this.delegate.needStartRecordAudio(0);
            MediaController.getInstance().stopRecording(0, false, 0);
        }
        this.recordingAudioVideo = false;
        updateRecordIntefrace();
    }

    public /* synthetic */ boolean lambda$new$14$ChatActivityEnterView(View view, MotionEvent motionEvent) {
        TLRPC.Chat chat;
        if (motionEvent.getAction() == 0) {
            if (this.recordCircle.isSendButtonVisible()) {
                if (!this.hasRecordVideo || this.calledRecordRunnable) {
                    this.startedDraggingX = -1.0f;
                    if (this.hasRecordVideo && this.videoSendButton.getTag() != null) {
                        this.delegate.needStartRecordVideo(1, true, 0);
                    } else {
                        if (this.recordingAudioVideo && isInScheduleMode()) {
                            AlertsCreator.createScheduleDatePickerDialog(this.parentActivity, UserObject.isUserSelf(this.parentFragment.getCurrentUser()), new AlertsCreator.ScheduleDatePickerDelegate() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$ChatActivityEnterView$O5zblFE-T18WziVszbq-50yuOKA
                                @Override // im.uwrkaxlmjj.ui.components.AlertsCreator.ScheduleDatePickerDelegate
                                public final void didSelectDate(boolean z, int i) {
                                    MediaController.getInstance().stopRecording(1, z, i);
                                }
                            }, new Runnable() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$ChatActivityEnterView$WlwfnUBpfcql2W6yRFBxv5Q5KJo
                                @Override // java.lang.Runnable
                                public final void run() {
                                    MediaController.getInstance().stopRecording(0, false, 0);
                                }
                            });
                        }
                        this.delegate.needStartRecordAudio(0);
                        MediaController.getInstance().stopRecording(isInScheduleMode() ? 3 : 1, true, 0);
                    }
                    this.recordingAudioVideo = false;
                    updateRecordIntefrace();
                }
                return false;
            }
            ChatActivity chatActivity = this.parentFragment;
            if (chatActivity != null && (chat = chatActivity.getCurrentChat()) != null && !ChatObject.canSendMedia(chat)) {
                this.delegate.needShowMediaBanHint();
                return false;
            }
            if (this.hasRecordVideo) {
                this.calledRecordRunnable = false;
                this.recordAudioVideoRunnableStarted = true;
                AndroidUtilities.runOnUIThread(this.recordAudioVideoRunnable, 150L);
            } else {
                this.recordAudioVideoRunnable.run();
            }
        } else if (motionEvent.getAction() == 1 || motionEvent.getAction() == 3) {
            if (this.recordCircle.isSendButtonVisible() || this.recordedAudioPanel.getVisibility() == 0) {
                return false;
            }
            if (this.recordAudioVideoRunnableStarted) {
                AndroidUtilities.cancelRunOnUIThread(this.recordAudioVideoRunnable);
                this.delegate.onSwitchRecordMode(this.videoSendButton.getTag() == null);
                setRecordVideoButtonVisible(this.videoSendButton.getTag() == null, true);
                performHapticFeedback(3);
                sendAccessibilityEvent(1);
            } else if (!this.hasRecordVideo || this.calledRecordRunnable) {
                this.startedDraggingX = -1.0f;
                if (this.hasRecordVideo && this.videoSendButton.getTag() != null) {
                    CameraController.getInstance().cancelOnInitRunnable(this.onFinishInitCameraRunnable);
                    this.delegate.needStartRecordVideo(1, true, 0);
                } else {
                    if (this.recordingAudioVideo && isInScheduleMode()) {
                        AlertsCreator.createScheduleDatePickerDialog(this.parentActivity, UserObject.isUserSelf(this.parentFragment.getCurrentUser()), new AlertsCreator.ScheduleDatePickerDelegate() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$ChatActivityEnterView$-AXv8GV-menvBrmh2_KSo-unoG4
                            @Override // im.uwrkaxlmjj.ui.components.AlertsCreator.ScheduleDatePickerDelegate
                            public final void didSelectDate(boolean z, int i) {
                                MediaController.getInstance().stopRecording(1, z, i);
                            }
                        }, new Runnable() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$ChatActivityEnterView$JApayKDhSbXIzoPGBYwwhvgOOB8
                            @Override // java.lang.Runnable
                            public final void run() {
                                MediaController.getInstance().stopRecording(0, false, 0);
                            }
                        });
                    }
                    this.delegate.needStartRecordAudio(0);
                    MediaController.getInstance().stopRecording(isInScheduleMode() ? 3 : 1, true, 0);
                }
                this.recordingAudioVideo = false;
                updateRecordIntefrace();
            }
        } else if (motionEvent.getAction() == 2 && this.recordingAudioVideo) {
            float x = motionEvent.getX();
            float y = motionEvent.getY();
            if (this.recordCircle.isSendButtonVisible()) {
                return false;
            }
            if (this.recordCircle.setLockTranslation(y) == 2) {
                AnimatorSet animatorSet = new AnimatorSet();
                RecordCircle recordCircle = this.recordCircle;
                animatorSet.playTogether(ObjectAnimator.ofFloat(recordCircle, "lockAnimatedTranslation", recordCircle.startTranslation), ObjectAnimator.ofFloat(this.slideText, (Property<LinearLayout, Float>) View.ALPHA, 0.0f), ObjectAnimator.ofFloat(this.slideText, (Property<LinearLayout, Float>) View.TRANSLATION_Y, AndroidUtilities.dp(20.0f)), ObjectAnimator.ofFloat(this.recordSendText, (Property<TextView, Float>) View.ALPHA, 1.0f), ObjectAnimator.ofFloat(this.recordSendText, (Property<TextView, Float>) View.TRANSLATION_Y, -AndroidUtilities.dp(20.0f), 0.0f));
                animatorSet.setInterpolator(new DecelerateInterpolator());
                animatorSet.setDuration(150L);
                animatorSet.start();
                return false;
            }
            if (x < (-this.distCanMove)) {
                if (this.hasRecordVideo && this.videoSendButton.getTag() != null) {
                    CameraController.getInstance().cancelOnInitRunnable(this.onFinishInitCameraRunnable);
                    this.delegate.needStartRecordVideo(2, true, 0);
                } else {
                    this.delegate.needStartRecordAudio(0);
                    MediaController.getInstance().stopRecording(0, false, 0);
                }
                this.recordingAudioVideo = false;
                updateRecordIntefrace();
            }
            float x2 = x + this.audioVideoButtonContainer.getX();
            FrameLayout.LayoutParams params = (FrameLayout.LayoutParams) this.slideText.getLayoutParams();
            float f = this.startedDraggingX;
            if (f != -1.0f) {
                float dist = x2 - f;
                params.leftMargin = AndroidUtilities.dp(30.0f) + ((int) dist);
                this.slideText.setLayoutParams(params);
                float alpha = (dist / this.distCanMove) + 1.0f;
                if (alpha > 1.0f) {
                    alpha = 1.0f;
                } else if (alpha < 0.0f) {
                    alpha = 0.0f;
                }
                this.slideText.setAlpha(alpha);
            }
            if (x2 <= this.slideText.getX() + this.slideText.getWidth() + AndroidUtilities.dp(30.0f) && this.startedDraggingX == -1.0f) {
                this.startedDraggingX = x2;
                float measuredWidth = ((this.recordPanel.getMeasuredWidth() - this.slideText.getMeasuredWidth()) - AndroidUtilities.dp(48.0f)) / 2.0f;
                this.distCanMove = measuredWidth;
                if (measuredWidth <= 0.0f || measuredWidth > AndroidUtilities.dp(80.0f)) {
                    this.distCanMove = AndroidUtilities.dp(80.0f);
                }
            }
            if (params.leftMargin > AndroidUtilities.dp(30.0f)) {
                params.leftMargin = AndroidUtilities.dp(30.0f);
                this.slideText.setLayoutParams(params);
                this.slideText.setAlpha(1.0f);
                this.startedDraggingX = -1.0f;
            }
        }
        view.onTouchEvent(motionEvent);
        return true;
    }

    public /* synthetic */ void lambda$new$15$ChatActivityEnterView(View view) {
        String text = this.messageEditText.getText().toString();
        int idx = text.indexOf(32);
        if (idx == -1 || idx == text.length() - 1) {
            setFieldText("");
        } else {
            setFieldText(text.substring(0, idx + 1));
        }
    }

    public /* synthetic */ void lambda$new$16$ChatActivityEnterView(View view) {
        sendMessage();
    }

    public /* synthetic */ void lambda$new$17$ChatActivityEnterView(View v) {
        ChatActivityEnterViewDelegate chatActivityEnterViewDelegate = this.delegate;
        if (chatActivityEnterViewDelegate != null) {
            SimpleTextView simpleTextView = this.slowModeButton;
            chatActivityEnterViewDelegate.onUpdateSlowModeButton(simpleTextView, true, simpleTextView.getText());
        }
    }

    public /* synthetic */ void lambda$new$18$ChatActivityEnterView(View v) {
        EmojiView emojiView;
        if (this.expandStickersButton.getVisibility() != 0 || this.expandStickersButton.getAlpha() != 1.0f) {
            return;
        }
        if (this.stickersExpanded) {
            if (this.searchingType != 0) {
                this.searchingType = 0;
                this.emojiView.closeSearch(true);
                this.emojiView.hideSearchKeyboard();
                if (this.emojiTabOpen) {
                    checkSendButton(true);
                }
            } else if (!this.stickersDragging && (emojiView = this.emojiView) != null) {
                emojiView.showSearchField(false);
            }
        } else if (!this.stickersDragging) {
            this.emojiView.showSearchField(true);
        }
        if (!this.stickersDragging) {
            setStickersExpanded(!this.stickersExpanded, true, false);
        }
    }

    public /* synthetic */ void lambda$new$19$ChatActivityEnterView(View view) {
        doneEditingMessage();
    }

    @Override // android.view.ViewGroup
    protected boolean drawChild(Canvas canvas, View child, long drawingTime) {
        if (child == this.topView) {
            canvas.save();
            canvas.clipRect(0, 0, getMeasuredWidth(), child.getLayoutParams().height + AndroidUtilities.dp(2.0f));
        }
        boolean result = super.drawChild(canvas, child, drawingTime);
        if (child == this.topView) {
            canvas.restore();
        }
        return result;
    }

    @Override // android.view.View
    protected void onDraw(Canvas canvas) {
        View view = this.topView;
        int top = (view == null || view.getVisibility() != 0) ? 0 : (int) this.topView.getTranslationY();
        int bottom = Theme.chat_composeShadowDrawable.getIntrinsicHeight() + top;
        Theme.chat_composeShadowDrawable.setBounds(0, top, getMeasuredWidth(), bottom);
        Theme.chat_composeShadowDrawable.draw(canvas);
        canvas.drawRect(0.0f, bottom, getWidth(), getHeight(), Theme.chat_composeBackgroundPaint);
    }

    @Override // android.view.View
    public boolean hasOverlappingRendering() {
        return false;
    }

    /* JADX WARN: Removed duplicated region for block: B:47:0x0153  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    private boolean onSendLongClick(android.view.View r20) {
        /*
            Method dump skipped, instruction units count: 399
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: im.uwrkaxlmjj.ui.components.ChatActivityEnterView.onSendLongClick(android.view.View):boolean");
    }

    public /* synthetic */ void lambda$onSendLongClick$20$ChatActivityEnterView(KeyEvent keyEvent) {
        ActionBarPopupWindow actionBarPopupWindow;
        if (keyEvent.getKeyCode() == 4 && keyEvent.getRepeatCount() == 0 && (actionBarPopupWindow = this.sendPopupWindow) != null && actionBarPopupWindow.isShowing()) {
            this.sendPopupWindow.dismiss();
        }
    }

    public /* synthetic */ void lambda$onSendLongClick$21$ChatActivityEnterView(int num, TLRPC.User user, View v) {
        ActionBarPopupWindow actionBarPopupWindow = this.sendPopupWindow;
        if (actionBarPopupWindow != null && actionBarPopupWindow.isShowing()) {
            this.sendPopupWindow.dismiss();
        }
        if (num == 0) {
            AlertsCreator.createScheduleDatePickerDialog(this.parentActivity, UserObject.isUserSelf(user), new $$Lambda$ChatActivityEnterView$JVdEEcN0cOJMJGELLq0jnEDl3Ac(this));
        } else if (num == 1) {
            sendMessageInternal(false, 0);
        }
    }

    public boolean isSendButtonVisible() {
        return this.sendButton.getVisibility() == 0;
    }

    private void setRecordVideoButtonVisible(boolean visible, boolean animated) {
        ImageView imageView = this.videoSendButton;
        if (imageView == null) {
            return;
        }
        imageView.setTag(visible ? 1 : null);
        AnimatorSet animatorSet = this.audioVideoButtonAnimation;
        if (animatorSet != null) {
            animatorSet.cancel();
            this.audioVideoButtonAnimation = null;
        }
        if (animated) {
            SharedPreferences preferences = MessagesController.getGlobalMainSettings();
            boolean isChannel = false;
            if (((int) this.dialog_id) < 0) {
                TLRPC.Chat chat = this.accountInstance.getMessagesController().getChat(Integer.valueOf(-((int) this.dialog_id)));
                isChannel = ChatObject.isChannel(chat) && !chat.megagroup;
            }
            preferences.edit().putBoolean(isChannel ? "currentModeVideoChannel" : "currentModeVideo", visible).commit();
            AnimatorSet animatorSet2 = new AnimatorSet();
            this.audioVideoButtonAnimation = animatorSet2;
            Animator[] animatorArr = new Animator[6];
            ImageView imageView2 = this.videoSendButton;
            Property property = View.SCALE_X;
            float[] fArr = new float[1];
            fArr[0] = visible ? 1.0f : 0.1f;
            animatorArr[0] = ObjectAnimator.ofFloat(imageView2, (Property<ImageView, Float>) property, fArr);
            ImageView imageView3 = this.videoSendButton;
            Property property2 = View.SCALE_Y;
            float[] fArr2 = new float[1];
            fArr2[0] = visible ? 1.0f : 0.1f;
            animatorArr[1] = ObjectAnimator.ofFloat(imageView3, (Property<ImageView, Float>) property2, fArr2);
            ImageView imageView4 = this.videoSendButton;
            Property property3 = View.ALPHA;
            float[] fArr3 = new float[1];
            fArr3[0] = visible ? 1.0f : 0.0f;
            animatorArr[2] = ObjectAnimator.ofFloat(imageView4, (Property<ImageView, Float>) property3, fArr3);
            ImageView imageView5 = this.audioSendButton;
            Property property4 = View.SCALE_X;
            float[] fArr4 = new float[1];
            fArr4[0] = visible ? 0.1f : 1.0f;
            animatorArr[3] = ObjectAnimator.ofFloat(imageView5, (Property<ImageView, Float>) property4, fArr4);
            ImageView imageView6 = this.audioSendButton;
            Property property5 = View.SCALE_Y;
            float[] fArr5 = new float[1];
            fArr5[0] = visible ? 0.1f : 1.0f;
            animatorArr[4] = ObjectAnimator.ofFloat(imageView6, (Property<ImageView, Float>) property5, fArr5);
            ImageView imageView7 = this.audioSendButton;
            Property property6 = View.ALPHA;
            float[] fArr6 = new float[1];
            fArr6[0] = visible ? 0.0f : 1.0f;
            animatorArr[5] = ObjectAnimator.ofFloat(imageView7, (Property<ImageView, Float>) property6, fArr6);
            animatorSet2.playTogether(animatorArr);
            this.audioVideoButtonAnimation.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.components.ChatActivityEnterView.19
                @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                public void onAnimationEnd(Animator animation) {
                    if (animation.equals(ChatActivityEnterView.this.audioVideoButtonAnimation)) {
                        ChatActivityEnterView.this.audioVideoButtonAnimation = null;
                    }
                    (ChatActivityEnterView.this.videoSendButton.getTag() == null ? ChatActivityEnterView.this.audioSendButton : ChatActivityEnterView.this.videoSendButton).sendAccessibilityEvent(8);
                }
            });
            this.audioVideoButtonAnimation.setInterpolator(new DecelerateInterpolator());
            this.audioVideoButtonAnimation.setDuration(150L);
            this.audioVideoButtonAnimation.start();
            return;
        }
        this.videoSendButton.setScaleX(visible ? 1.0f : 0.1f);
        this.videoSendButton.setScaleY(visible ? 1.0f : 0.1f);
        this.videoSendButton.setAlpha(visible ? 1.0f : 0.0f);
        this.audioSendButton.setScaleX(visible ? 0.1f : 1.0f);
        this.audioSendButton.setScaleY(visible ? 0.1f : 1.0f);
        this.audioSendButton.setAlpha(visible ? 0.0f : 1.0f);
    }

    public boolean isRecordingAudioVideo() {
        return this.recordingAudioVideo;
    }

    public boolean isRecordLocked() {
        return this.recordingAudioVideo && this.recordCircle.isSendButtonVisible();
    }

    public void cancelRecordingAudioVideo() {
        if (this.hasRecordVideo && this.videoSendButton.getTag() != null) {
            CameraController.getInstance().cancelOnInitRunnable(this.onFinishInitCameraRunnable);
            this.delegate.needStartRecordVideo(2, true, 0);
        } else {
            this.delegate.needStartRecordAudio(0);
            MediaController.getInstance().stopRecording(0, false, 0);
        }
        this.recordingAudioVideo = false;
        updateRecordIntefrace();
    }

    public void showContextProgress(boolean show) {
        CloseProgressDrawable2 closeProgressDrawable2 = this.progressDrawable;
        if (closeProgressDrawable2 == null) {
            return;
        }
        if (show) {
            closeProgressDrawable2.startAnimation();
        } else {
            closeProgressDrawable2.stopAnimation();
        }
    }

    public void setCaption(String caption) {
        EditTextCaption editTextCaption = this.messageEditText;
        if (editTextCaption != null) {
            editTextCaption.setCaption(caption);
            checkSendButton(true);
        }
    }

    public void setSlowModeTimer(int time) {
        this.slowModeTimer = time;
        updateSlowModeText();
    }

    public CharSequence getSlowModeTimer() {
        if (this.slowModeTimer > 0) {
            return this.slowModeButton.getText();
        }
        return null;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void updateSlowModeText() {
        int currentTime;
        boolean isUploading;
        int serverTime = ConnectionsManager.getInstance(this.currentAccount).getCurrentTime();
        AndroidUtilities.cancelRunOnUIThread(this.updateSlowModeRunnable);
        this.updateSlowModeRunnable = null;
        TLRPC.ChatFull chatFull = this.info;
        if (chatFull == null || chatFull.slowmode_seconds == 0 || this.info.slowmode_next_send_date > serverTime || !((isUploading = SendMessagesHelper.getInstance(this.currentAccount).isUploadingMessageIdDialog(this.dialog_id)) || SendMessagesHelper.getInstance(this.currentAccount).isSendingMessageIdDialog(this.dialog_id))) {
            int i = this.slowModeTimer;
            if (i >= 2147483646) {
                currentTime = 0;
                if (this.info != null) {
                    this.accountInstance.getMessagesController().loadFullChat(this.info.id, 0, true);
                }
            } else {
                currentTime = i - serverTime;
            }
        } else {
            TLRPC.Chat chat = this.accountInstance.getMessagesController().getChat(Integer.valueOf(this.info.id));
            if (!ChatObject.hasAdminRights(chat)) {
                currentTime = this.info.slowmode_seconds;
                this.slowModeTimer = isUploading ? Integer.MAX_VALUE : 2147483646;
            } else {
                currentTime = 0;
            }
        }
        if (this.slowModeTimer != 0 && currentTime > 0) {
            int minutes = currentTime / 60;
            int seconds = currentTime - (minutes * 60);
            if (minutes == 0 && seconds == 0) {
                seconds = 1;
            }
            this.slowModeButton.setText(String.format("%d:%02d", Integer.valueOf(minutes), Integer.valueOf(seconds)));
            ChatActivityEnterViewDelegate chatActivityEnterViewDelegate = this.delegate;
            if (chatActivityEnterViewDelegate != null) {
                SimpleTextView simpleTextView = this.slowModeButton;
                chatActivityEnterViewDelegate.onUpdateSlowModeButton(simpleTextView, false, simpleTextView.getText());
            }
            Runnable runnable = new Runnable() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$ChatActivityEnterView$qyshjlBTlPZTJLsPdbUJ8uQfr4I
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.updateSlowModeText();
                }
            };
            this.updateSlowModeRunnable = runnable;
            AndroidUtilities.runOnUIThread(runnable, 100L);
        } else {
            this.slowModeTimer = 0;
        }
        if (!isInScheduleMode()) {
            checkSendButton(true);
        }
    }

    public void addTopView(View view, View lineView, int height) {
        if (view == null) {
            return;
        }
        this.topLineView = lineView;
        lineView.setVisibility(8);
        this.topLineView.setAlpha(0.0f);
        addView(this.topLineView, LayoutHelper.createFrame(-1.0f, 1.0f, 51, 0.0f, height + 1, 0.0f, 0.0f));
        this.topView = view;
        view.setVisibility(8);
        this.topView.setTranslationY(height);
        addView(this.topView, 0, LayoutHelper.createFrame(-1.0f, height, 51, 0.0f, 2.0f, 0.0f, 0.0f));
        this.needShowTopView = false;
    }

    public void setForceShowSendButton(boolean value, boolean animated) {
        this.forceShowSendButton = value;
        checkSendButton(animated);
    }

    public void setAllowStickersAndGifs(boolean value, boolean value2) {
        if ((this.allowStickers != value || this.allowGifs != value2) && this.emojiView != null) {
            if (this.emojiViewVisible) {
                hidePopup(false);
            }
            this.sizeNotifierLayout.removeView(this.emojiView);
            this.emojiView = null;
        }
        this.allowStickers = value;
        this.allowGifs = value2;
        setEmojiButtonImage(false, !this.isPaused);
    }

    public void addEmojiToRecent(String code) {
        createEmojiView();
        this.emojiView.addEmojiToRecent(code);
    }

    public void setOpenGifsTabFirst() {
        createEmojiView();
        MediaDataController.getInstance(this.currentAccount).loadRecents(0, true, true, false);
        this.emojiView.switchToGifRecent();
    }

    public void showTopView(boolean animated, boolean openKeyboard) {
        if (this.topView == null || this.topViewShowed || getVisibility() != 0) {
            if (this.recordedAudioPanel.getVisibility() != 0) {
                if (!this.forceShowSendButton || openKeyboard) {
                    openKeyboard();
                    return;
                }
                return;
            }
            return;
        }
        this.needShowTopView = true;
        this.topViewShowed = true;
        if (this.allowShowTopView) {
            this.topView.setVisibility(0);
            this.topLineView.setVisibility(0);
            AnimatorSet animatorSet = this.currentTopViewAnimation;
            if (animatorSet != null) {
                animatorSet.cancel();
                this.currentTopViewAnimation = null;
            }
            resizeForTopView(true);
            if (animated) {
                AnimatorSet animatorSet2 = new AnimatorSet();
                this.currentTopViewAnimation = animatorSet2;
                animatorSet2.playTogether(ObjectAnimator.ofFloat(this.topView, (Property<View, Float>) View.TRANSLATION_Y, 0.0f), ObjectAnimator.ofFloat(this.topLineView, (Property<View, Float>) View.ALPHA, 1.0f));
                this.currentTopViewAnimation.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.components.ChatActivityEnterView.20
                    @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                    public void onAnimationEnd(Animator animation) {
                        if (ChatActivityEnterView.this.currentTopViewAnimation != null && ChatActivityEnterView.this.currentTopViewAnimation.equals(animation)) {
                            ChatActivityEnterView.this.currentTopViewAnimation = null;
                        }
                    }
                });
                this.currentTopViewAnimation.setDuration(250L);
                this.currentTopViewAnimation.setInterpolator(CubicBezierInterpolator.DEFAULT);
                this.currentTopViewAnimation.start();
            } else {
                this.topView.setTranslationY(0.0f);
                this.topLineView.setAlpha(1.0f);
            }
            if (this.recordedAudioPanel.getVisibility() != 0) {
                if (!this.forceShowSendButton || openKeyboard) {
                    this.messageEditText.requestFocus();
                    openKeyboard();
                }
            }
        }
    }

    public void onEditTimeExpired() {
        this.doneButtonContainer.setVisibility(8);
    }

    public void showEditDoneProgress(final boolean show, boolean animated) {
        AnimatorSet animatorSet = this.doneButtonAnimation;
        if (animatorSet != null) {
            animatorSet.cancel();
        }
        if (animated) {
            this.doneButtonAnimation = new AnimatorSet();
            if (show) {
                this.doneButtonProgress.setVisibility(0);
                this.doneButtonContainer.setEnabled(false);
                this.doneButtonAnimation.playTogether(ObjectAnimator.ofFloat(this.doneButtonImage, (Property<ImageView, Float>) View.SCALE_X, 0.1f), ObjectAnimator.ofFloat(this.doneButtonImage, (Property<ImageView, Float>) View.SCALE_Y, 0.1f), ObjectAnimator.ofFloat(this.doneButtonImage, (Property<ImageView, Float>) View.ALPHA, 0.0f), ObjectAnimator.ofFloat(this.doneButtonProgress, (Property<ContextProgressView, Float>) View.SCALE_X, 1.0f), ObjectAnimator.ofFloat(this.doneButtonProgress, (Property<ContextProgressView, Float>) View.SCALE_Y, 1.0f), ObjectAnimator.ofFloat(this.doneButtonProgress, (Property<ContextProgressView, Float>) View.ALPHA, 1.0f));
            } else {
                this.doneButtonImage.setVisibility(0);
                this.doneButtonContainer.setEnabled(true);
                this.doneButtonAnimation.playTogether(ObjectAnimator.ofFloat(this.doneButtonProgress, (Property<ContextProgressView, Float>) View.SCALE_X, 0.1f), ObjectAnimator.ofFloat(this.doneButtonProgress, (Property<ContextProgressView, Float>) View.SCALE_Y, 0.1f), ObjectAnimator.ofFloat(this.doneButtonProgress, (Property<ContextProgressView, Float>) View.ALPHA, 0.0f), ObjectAnimator.ofFloat(this.doneButtonImage, (Property<ImageView, Float>) View.SCALE_X, 1.0f), ObjectAnimator.ofFloat(this.doneButtonImage, (Property<ImageView, Float>) View.SCALE_Y, 1.0f), ObjectAnimator.ofFloat(this.doneButtonImage, (Property<ImageView, Float>) View.ALPHA, 1.0f));
            }
            this.doneButtonAnimation.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.components.ChatActivityEnterView.21
                @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                public void onAnimationEnd(Animator animation) {
                    if (ChatActivityEnterView.this.doneButtonAnimation != null && ChatActivityEnterView.this.doneButtonAnimation.equals(animation)) {
                        if (!show) {
                            ChatActivityEnterView.this.doneButtonProgress.setVisibility(4);
                        } else {
                            ChatActivityEnterView.this.doneButtonImage.setVisibility(4);
                        }
                    }
                }

                @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                public void onAnimationCancel(Animator animation) {
                    if (ChatActivityEnterView.this.doneButtonAnimation != null && ChatActivityEnterView.this.doneButtonAnimation.equals(animation)) {
                        ChatActivityEnterView.this.doneButtonAnimation = null;
                    }
                }
            });
            this.doneButtonAnimation.setDuration(150L);
            this.doneButtonAnimation.start();
            return;
        }
        if (show) {
            this.doneButtonImage.setScaleX(0.1f);
            this.doneButtonImage.setScaleY(0.1f);
            this.doneButtonImage.setAlpha(0.0f);
            this.doneButtonProgress.setScaleX(1.0f);
            this.doneButtonProgress.setScaleY(1.0f);
            this.doneButtonProgress.setAlpha(1.0f);
            this.doneButtonImage.setVisibility(4);
            this.doneButtonProgress.setVisibility(0);
            this.doneButtonContainer.setEnabled(false);
            return;
        }
        this.doneButtonProgress.setScaleX(0.1f);
        this.doneButtonProgress.setScaleY(0.1f);
        this.doneButtonProgress.setAlpha(0.0f);
        this.doneButtonImage.setScaleX(1.0f);
        this.doneButtonImage.setScaleY(1.0f);
        this.doneButtonImage.setAlpha(1.0f);
        this.doneButtonImage.setVisibility(0);
        this.doneButtonProgress.setVisibility(4);
        this.doneButtonContainer.setEnabled(true);
    }

    public void hideTopView(boolean animated) {
        if (this.topView == null || !this.topViewShowed) {
            return;
        }
        this.topViewShowed = false;
        this.needShowTopView = false;
        if (this.allowShowTopView) {
            AnimatorSet animatorSet = this.currentTopViewAnimation;
            if (animatorSet != null) {
                animatorSet.cancel();
                this.currentTopViewAnimation = null;
            }
            if (animated) {
                AnimatorSet animatorSet2 = new AnimatorSet();
                this.currentTopViewAnimation = animatorSet2;
                animatorSet2.playTogether(ObjectAnimator.ofFloat(this.topView, (Property<View, Float>) View.TRANSLATION_Y, this.topView.getLayoutParams().height), ObjectAnimator.ofFloat(this.topLineView, (Property<View, Float>) View.ALPHA, 0.0f));
                this.currentTopViewAnimation.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.components.ChatActivityEnterView.22
                    @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                    public void onAnimationEnd(Animator animation) {
                        if (ChatActivityEnterView.this.currentTopViewAnimation != null && ChatActivityEnterView.this.currentTopViewAnimation.equals(animation)) {
                            ChatActivityEnterView.this.topView.setVisibility(8);
                            ChatActivityEnterView.this.topLineView.setVisibility(8);
                            ChatActivityEnterView.this.resizeForTopView(false);
                            ChatActivityEnterView.this.currentTopViewAnimation = null;
                        }
                    }

                    @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                    public void onAnimationCancel(Animator animation) {
                        if (ChatActivityEnterView.this.currentTopViewAnimation != null && ChatActivityEnterView.this.currentTopViewAnimation.equals(animation)) {
                            ChatActivityEnterView.this.currentTopViewAnimation = null;
                        }
                    }
                });
                this.currentTopViewAnimation.setDuration(200L);
                this.currentTopViewAnimation.setInterpolator(CubicBezierInterpolator.DEFAULT);
                this.currentTopViewAnimation.start();
                return;
            }
            this.topView.setVisibility(8);
            this.topLineView.setVisibility(8);
            this.topLineView.setAlpha(0.0f);
            resizeForTopView(false);
            this.topView.setTranslationY(r0.getLayoutParams().height);
        }
    }

    public boolean isTopViewVisible() {
        View view = this.topView;
        return view != null && view.getVisibility() == 0;
    }

    private void onWindowSizeChanged() {
        int size = this.sizeNotifierLayout.getHeight();
        if (!this.keyboardVisible) {
            size -= this.emojiPadding;
        }
        ChatActivityEnterViewDelegate chatActivityEnterViewDelegate = this.delegate;
        if (chatActivityEnterViewDelegate != null) {
            chatActivityEnterViewDelegate.onWindowSizeChanged(size);
        }
        if (this.topView != null) {
            if (size < AndroidUtilities.dp(72.0f) + ActionBar.getCurrentActionBarHeight()) {
                if (this.allowShowTopView) {
                    this.allowShowTopView = false;
                    if (this.needShowTopView) {
                        this.topView.setVisibility(8);
                        this.topLineView.setVisibility(8);
                        this.topLineView.setAlpha(0.0f);
                        resizeForTopView(false);
                        this.topView.setTranslationY(r1.getLayoutParams().height);
                        return;
                    }
                    return;
                }
                return;
            }
            if (!this.allowShowTopView) {
                this.allowShowTopView = true;
                if (this.needShowTopView) {
                    this.topView.setVisibility(0);
                    this.topLineView.setVisibility(0);
                    this.topLineView.setAlpha(1.0f);
                    resizeForTopView(true);
                    this.topView.setTranslationY(0.0f);
                }
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void resizeForTopView(boolean show) {
        FrameLayout.LayoutParams layoutParams = (FrameLayout.LayoutParams) this.textFieldContainer.getLayoutParams();
        layoutParams.topMargin = AndroidUtilities.dp(2.0f) + (show ? this.topView.getLayoutParams().height : 0);
        this.textFieldContainer.setLayoutParams(layoutParams);
        setMinimumHeight(AndroidUtilities.dp(51.0f) + (show ? this.topView.getLayoutParams().height : 0));
        if (this.stickersExpanded) {
            if (this.searchingType == 0) {
                setStickersExpanded(false, true, false);
            } else {
                checkStickresExpandHeight();
            }
        }
    }

    public void onDestroy() {
        this.destroyed = true;
        NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.recordStarted);
        NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.recordStartError);
        NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.recordStopped);
        NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.recordProgressChanged);
        NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.closeChats);
        NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.audioDidSent);
        NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.audioRouteChanged);
        NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.messagePlayingDidReset);
        NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.messagePlayingProgressDidChanged);
        NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.featuredStickersDidLoad);
        NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.messageReceivedByServer);
        NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.sendingMessagesChanged);
        NotificationCenter.getGlobalInstance().removeObserver(this, NotificationCenter.emojiDidLoad);
        EmojiView emojiView = this.emojiView;
        if (emojiView != null) {
            emojiView.onDestroy();
        }
        Runnable runnable = this.updateSlowModeRunnable;
        if (runnable != null) {
            AndroidUtilities.cancelRunOnUIThread(runnable);
            this.updateSlowModeRunnable = null;
        }
        PowerManager.WakeLock wakeLock = this.wakeLock;
        if (wakeLock != null) {
            try {
                wakeLock.release();
                this.wakeLock = null;
            } catch (Exception e) {
                FileLog.e(e);
            }
        }
        SizeNotifierFrameLayout sizeNotifierFrameLayout = this.sizeNotifierLayout;
        if (sizeNotifierFrameLayout != null) {
            sizeNotifierFrameLayout.setDelegate(null);
        }
    }

    public void checkChannelRights() {
        TLRPC.Chat chat;
        ChatActivity chatActivity = this.parentFragment;
        if (chatActivity != null && (chat = chatActivity.getCurrentChat()) != null) {
            this.audioVideoButtonContainer.setAlpha(ChatObject.canSendMedia(chat) ? 1.0f : 0.5f);
            EmojiView emojiView = this.emojiView;
            if (emojiView != null) {
                emojiView.setStickersBanned(!ChatObject.canSendStickers(chat), chat.id);
            }
        }
    }

    public void onBeginHide() {
        Runnable runnable = this.focusRunnable;
        if (runnable != null) {
            AndroidUtilities.cancelRunOnUIThread(runnable);
            this.focusRunnable = null;
        }
    }

    public void onPause() {
        this.isPaused = true;
        closeKeyboard();
    }

    public void onResume() {
        this.isPaused = false;
        getVisibility();
        if (this.showKeyboardOnResume) {
            this.showKeyboardOnResume = false;
            if (this.searchingType == 0) {
                this.messageEditText.requestFocus();
            }
            AndroidUtilities.showKeyboard(this.messageEditText);
            if (!AndroidUtilities.usingHardwareInput && !this.keyboardVisible && !AndroidUtilities.isInMultiwindow) {
                this.waitingForKeyboardOpen = true;
                AndroidUtilities.cancelRunOnUIThread(this.openKeyboardRunnable);
                AndroidUtilities.runOnUIThread(this.openKeyboardRunnable, 100L);
            }
        }
    }

    @Override // android.view.View
    public void setVisibility(int visibility) {
        super.setVisibility(visibility);
        this.messageEditText.setEnabled(visibility == 0);
    }

    public void setDialogId(long id, int account) {
        this.dialog_id = id;
        int i = this.currentAccount;
        if (i != account) {
            NotificationCenter.getInstance(i).removeObserver(this, NotificationCenter.recordStarted);
            NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.recordStartError);
            NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.recordStopped);
            NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.recordProgressChanged);
            NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.closeChats);
            NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.audioDidSent);
            NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.audioRouteChanged);
            NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.messagePlayingDidReset);
            NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.messagePlayingProgressDidChanged);
            NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.featuredStickersDidLoad);
            NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.messageReceivedByServer);
            NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.sendingMessagesChanged);
            this.currentAccount = account;
            this.accountInstance = AccountInstance.getInstance(account);
            NotificationCenter.getInstance(this.currentAccount).addObserver(this, NotificationCenter.recordStarted);
            NotificationCenter.getInstance(this.currentAccount).addObserver(this, NotificationCenter.recordStartError);
            NotificationCenter.getInstance(this.currentAccount).addObserver(this, NotificationCenter.recordStopped);
            NotificationCenter.getInstance(this.currentAccount).addObserver(this, NotificationCenter.recordProgressChanged);
            NotificationCenter.getInstance(this.currentAccount).addObserver(this, NotificationCenter.closeChats);
            NotificationCenter.getInstance(this.currentAccount).addObserver(this, NotificationCenter.audioDidSent);
            NotificationCenter.getInstance(this.currentAccount).addObserver(this, NotificationCenter.audioRouteChanged);
            NotificationCenter.getInstance(this.currentAccount).addObserver(this, NotificationCenter.messagePlayingDidReset);
            NotificationCenter.getInstance(this.currentAccount).addObserver(this, NotificationCenter.messagePlayingProgressDidChanged);
            NotificationCenter.getInstance(this.currentAccount).addObserver(this, NotificationCenter.featuredStickersDidLoad);
            NotificationCenter.getInstance(this.currentAccount).addObserver(this, NotificationCenter.messageReceivedByServer);
            NotificationCenter.getInstance(this.currentAccount).addObserver(this, NotificationCenter.sendingMessagesChanged);
        }
        updateScheduleButton(false);
        checkRoundVideo();
        updateFieldHint();
    }

    public void setChatInfo(TLRPC.ChatFull chatInfo) {
        this.info = chatInfo;
        EmojiView emojiView = this.emojiView;
        if (emojiView != null) {
            emojiView.setChatInfo(chatInfo);
        }
        setSlowModeTimer(chatInfo.slowmode_next_send_date);
    }

    public void checkRoundVideo() {
        if (this.hasRecordVideo) {
            return;
        }
        if (this.attachLayout == null || Build.VERSION.SDK_INT < 18) {
            this.hasRecordVideo = false;
            setRecordVideoButtonVisible(false, false);
            return;
        }
        long j = this.dialog_id;
        int lower_id = (int) j;
        int high_id = (int) (j >> 32);
        if (lower_id == 0 && high_id != 0) {
            TLRPC.EncryptedChat encryptedChat = this.accountInstance.getMessagesController().getEncryptedChat(Integer.valueOf(high_id));
            if (AndroidUtilities.getPeerLayerVersion(encryptedChat.layer) >= 66) {
                this.hasRecordVideo = true;
            }
        } else {
            this.hasRecordVideo = true;
        }
        boolean isChannel = false;
        if (((int) this.dialog_id) < 0) {
            TLRPC.Chat chat = this.accountInstance.getMessagesController().getChat(Integer.valueOf(-((int) this.dialog_id)));
            isChannel = ChatObject.isChannel(chat) && !chat.megagroup;
            if (isChannel && !chat.creator && (chat.admin_rights == null || !chat.admin_rights.post_messages)) {
                this.hasRecordVideo = false;
            }
        }
        if (!SharedConfig.inappCamera) {
            this.hasRecordVideo = false;
        }
        if (this.hasRecordVideo) {
            if (SharedConfig.hasCameraCache) {
                CameraController.getInstance().initCamera(null);
            }
            SharedPreferences preferences = MessagesController.getGlobalMainSettings();
            boolean currentModeVideo = preferences.getBoolean(isChannel ? "currentModeVideoChannel" : "currentModeVideo", isChannel);
            setRecordVideoButtonVisible(currentModeVideo, false);
            return;
        }
        setRecordVideoButtonVisible(false, false);
    }

    public boolean isInVideoMode() {
        return this.videoSendButton.getTag() != null;
    }

    public boolean hasRecordVideo() {
        return this.hasRecordVideo;
    }

    private void updateFieldHint() {
        boolean isChannel = false;
        if (((int) this.dialog_id) < 0) {
            TLRPC.Chat chat = this.accountInstance.getMessagesController().getChat(Integer.valueOf(-((int) this.dialog_id)));
            isChannel = ChatObject.isChannel(chat) && !chat.megagroup;
        }
        if (this.editingMessageObject == null && isChannel) {
        }
    }

    public void setReplyingMessageObject(MessageObject messageObject) {
        MessageObject messageObject2;
        if (messageObject != null) {
            if (this.botMessageObject == null && (messageObject2 = this.botButtonsMessageObject) != this.replyingMessageObject) {
                this.botMessageObject = messageObject2;
            }
            this.replyingMessageObject = messageObject;
            setButtons(messageObject, true);
        } else if (messageObject == null && this.replyingMessageObject == this.botButtonsMessageObject) {
            this.replyingMessageObject = null;
            setButtons(this.botMessageObject, false);
            this.botMessageObject = null;
        } else {
            this.replyingMessageObject = messageObject;
        }
        MediaController.getInstance().setReplyingMessage(messageObject);
    }

    public void setWebPage(TLRPC.WebPage webPage, boolean searchWebPages) {
        this.messageWebPage = webPage;
        this.messageWebPageSearch = searchWebPages;
    }

    public boolean isMessageWebPageSearchEnabled() {
        return this.messageWebPageSearch;
    }

    private void hideRecordedAudioPanel() {
        this.audioToSendPath = null;
        this.audioToSend = null;
        this.audioToSendMessageObject = null;
        this.videoToSendMessageObject = null;
        this.videoTimelineView.destroy();
        AnimatorSet AnimatorSet = new AnimatorSet();
        AnimatorSet.playTogether(ObjectAnimator.ofFloat(this.recordedAudioPanel, (Property<FrameLayout, Float>) View.ALPHA, 0.0f));
        AnimatorSet.setDuration(200L);
        AnimatorSet.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.components.ChatActivityEnterView.23
            @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
            public void onAnimationEnd(Animator animation) {
                ChatActivityEnterView.this.recordedAudioPanel.setVisibility(8);
            }
        });
        AnimatorSet.start();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void sendMessage() {
        if (isInScheduleMode()) {
            AlertsCreator.createScheduleDatePickerDialog(this.parentActivity, UserObject.isUserSelf(this.parentFragment.getCurrentUser()), new $$Lambda$ChatActivityEnterView$JVdEEcN0cOJMJGELLq0jnEDl3Ac(this));
        } else {
            sendMessageInternal(true, 0);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void sendMessageInternal(boolean notify, int scheduleDate) {
        ChatActivityEnterViewDelegate chatActivityEnterViewDelegate;
        TLRPC.Chat chat;
        if (this.slowModeTimer == Integer.MAX_VALUE && !isInScheduleMode()) {
            ChatActivityEnterViewDelegate chatActivityEnterViewDelegate2 = this.delegate;
            if (chatActivityEnterViewDelegate2 != null) {
                chatActivityEnterViewDelegate2.scrollToSendingMessage();
                return;
            }
            return;
        }
        ChatActivity chatActivity = this.parentFragment;
        if (chatActivity != null) {
            TLRPC.Chat chat2 = chatActivity.getCurrentChat();
            TLRPC.User user = this.parentFragment.getCurrentUser();
            if (user != null || ((ChatObject.isChannel(chat2) && chat2.megagroup) || !ChatObject.isChannel(chat2))) {
                MessagesController.getNotificationsSettings(this.currentAccount).edit().putBoolean("silent_" + this.dialog_id, !notify).commit();
            }
        }
        if (this.stickersExpanded) {
            setStickersExpanded(false, true, false);
            if (this.searchingType != 0) {
                this.emojiView.closeSearch(false);
                this.emojiView.hideSearchKeyboard();
            }
        }
        if (this.videoToSendMessageObject != null) {
            this.delegate.needStartRecordVideo(4, notify, scheduleDate);
            hideRecordedAudioPanel();
            checkSendButton(true);
            return;
        }
        if (this.audioToSend == null) {
            CharSequence message = this.messageEditText.getText();
            ChatActivity chatActivity2 = this.parentFragment;
            if (chatActivity2 != null && (chat = chatActivity2.getCurrentChat()) != null && chat.slowmode_enabled && !ChatObject.hasAdminRights(chat)) {
                if (message.length() > this.accountInstance.getMessagesController().maxMessageLength) {
                    AlertsCreator.showSimpleAlert(this.parentFragment, LocaleController.getString("Slowmode", R.string.Slowmode), LocaleController.getString("SlowmodeSendErrorTooLong", R.string.SlowmodeSendErrorTooLong));
                    return;
                } else if (this.forceShowSendButton && message.length() > 0) {
                    AlertsCreator.showSimpleAlert(this.parentFragment, LocaleController.getString("Slowmode", R.string.Slowmode), LocaleController.getString("SlowmodeSendError", R.string.SlowmodeSendError));
                    return;
                }
            }
            if (processSendingText(message, notify, scheduleDate)) {
                this.messageEditText.setText("");
                this.lastTypingTimeSend = 0L;
                ChatActivityEnterViewDelegate chatActivityEnterViewDelegate3 = this.delegate;
                if (chatActivityEnterViewDelegate3 != null) {
                    chatActivityEnterViewDelegate3.onMessageSend(message, notify, scheduleDate);
                    return;
                }
                return;
            }
            if (this.forceShowSendButton && (chatActivityEnterViewDelegate = this.delegate) != null) {
                chatActivityEnterViewDelegate.onMessageSend(null, notify, scheduleDate);
                return;
            }
            return;
        }
        MessageObject playing = MediaController.getInstance().getPlayingMessageObject();
        if (playing != null && playing == this.audioToSendMessageObject) {
            MediaController.getInstance().cleanupPlayer(true, true);
        }
        SendMessagesHelper.getInstance(this.currentAccount).sendMessage(this.audioToSend, null, this.audioToSendPath, this.dialog_id, this.replyingMessageObject, null, null, null, null, notify, scheduleDate, 0, null);
        ChatActivityEnterViewDelegate chatActivityEnterViewDelegate4 = this.delegate;
        if (chatActivityEnterViewDelegate4 != null) {
            chatActivityEnterViewDelegate4.onMessageSend(null, notify, scheduleDate);
        }
        hideRecordedAudioPanel();
        checkSendButton(true);
    }

    public void doneEditingMessage() {
        if (this.editingMessageObject != null) {
            this.delegate.onMessageEditEnd(true);
            showEditDoneProgress(true, true);
            CharSequence[] message = {this.messageEditText.getText()};
            ArrayList<TLRPC.MessageEntity> entities = MediaDataController.getInstance(this.currentAccount).getEntities(message);
            this.editingMessageReqId = SendMessagesHelper.getInstance(this.currentAccount).editMessage(this.editingMessageObject, message[0].toString(), this.messageWebPageSearch, this.parentFragment, entities, this.editingMessageObject.scheduled ? this.editingMessageObject.messageOwner.date : 0, new Runnable() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$ChatActivityEnterView$cy5AU3v9nVJMwuxfEUHK6H_MbIc
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$doneEditingMessage$22$ChatActivityEnterView();
                }
            });
        }
    }

    public /* synthetic */ void lambda$doneEditingMessage$22$ChatActivityEnterView() {
        this.editingMessageReqId = 0;
        setEditingMessageObject(null, false);
    }

    public boolean processSendingText(CharSequence text, boolean notify, int scheduleDate) {
        CharSequence text2 = AndroidUtilities.getTrimmedString(text);
        int maxLength = this.accountInstance.getMessagesController().maxMessageLength;
        if (text2.length() == 0) {
            return false;
        }
        int count = (int) Math.ceil(text2.length() / maxLength);
        for (int a = 0; a < count; a++) {
            CharSequence[] message = {text2.subSequence(a * maxLength, Math.min((a + 1) * maxLength, text2.length()))};
            ArrayList<TLRPC.MessageEntity> entities = MediaDataController.getInstance(this.currentAccount).getEntities(message);
            int lower_part = (int) this.dialog_id;
            if (lower_part < 0) {
                int chatId = -lower_part;
                TLRPC.Chat chat = MessagesController.getInstance(UserConfig.selectedAccount).getChat(Integer.valueOf(chatId));
                if (!ChatObject.canUserDoAction(chat, 9) && RegexUtils.hasLink(message[0].toString())) {
                    WalletDialogUtil.showSingleBtnWalletDialog(this.parentFragment, LocaleController.getString(R.string.YouHaveNoPermissionToSendMsgTips), null, true, null, null);
                    return false;
                }
            }
            int chatId2 = this.currentAccount;
            SendMessagesHelper.getInstance(chatId2).sendMessage(message[0].toString(), this.dialog_id, this.replyingMessageObject, this.messageWebPage, this.messageWebPageSearch, entities, null, null, notify, scheduleDate);
        }
        return true;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void checkSendButton(boolean animated) {
        boolean animated2;
        int color;
        int i;
        int i2;
        if (this.editingMessageObject != null) {
            return;
        }
        if (!this.isPaused) {
            animated2 = animated;
        } else {
            animated2 = false;
        }
        CharSequence message = AndroidUtilities.getTrimmedString(this.messageEditText.getText());
        int i3 = this.slowModeTimer;
        if (i3 > 0 && i3 != Integer.MAX_VALUE && !isInScheduleMode()) {
            if (this.slowModeButton.getVisibility() != 0) {
                if (animated2) {
                    if (this.runningAnimationType == 5) {
                        return;
                    }
                    AnimatorSet animatorSet = this.runningAnimation;
                    if (animatorSet != null) {
                        animatorSet.cancel();
                        this.runningAnimation = null;
                    }
                    AnimatorSet animatorSet2 = this.runningAnimation2;
                    if (animatorSet2 != null) {
                        animatorSet2.cancel();
                        this.runningAnimation2 = null;
                    }
                    if (this.attachLayout != null) {
                        this.runningAnimation2 = new AnimatorSet();
                        ArrayList<Animator> animators = new ArrayList<>();
                        animators.add(ObjectAnimator.ofFloat(this.attachLayout, (Property<LinearLayout, Float>) View.ALPHA, 0.0f));
                        animators.add(ObjectAnimator.ofFloat(this.attachLayout, (Property<LinearLayout, Float>) View.SCALE_X, 0.0f));
                        this.scheduleButtonHidden = false;
                        ChatActivityEnterViewDelegate chatActivityEnterViewDelegate = this.delegate;
                        boolean hasScheduled = chatActivityEnterViewDelegate != null && chatActivityEnterViewDelegate.hasScheduledMessages();
                        ImageView imageView = this.scheduledButton;
                        if (imageView != null) {
                            imageView.setScaleY(1.0f);
                            if (hasScheduled) {
                                this.scheduledButton.setVisibility(0);
                                this.scheduledButton.setTag(1);
                                this.scheduledButton.setPivotX(AndroidUtilities.dp(48.0f));
                                ImageView imageView2 = this.scheduledButton;
                                Property property = View.TRANSLATION_X;
                                float[] fArr = new float[1];
                                ImageView imageView3 = this.botButton;
                                fArr[0] = AndroidUtilities.dp((imageView3 == null || imageView3.getVisibility() != 0) ? 48.0f : 96.0f);
                                animators.add(ObjectAnimator.ofFloat(imageView2, (Property<ImageView, Float>) property, fArr));
                                animators.add(ObjectAnimator.ofFloat(this.scheduledButton, (Property<ImageView, Float>) View.ALPHA, 1.0f));
                                animators.add(ObjectAnimator.ofFloat(this.scheduledButton, (Property<ImageView, Float>) View.SCALE_X, 1.0f));
                            } else {
                                ImageView imageView4 = this.scheduledButton;
                                ImageView imageView5 = this.botButton;
                                imageView4.setTranslationX(AndroidUtilities.dp((imageView5 == null || imageView5.getVisibility() != 0) ? 48.0f : 96.0f));
                                this.scheduledButton.setAlpha(1.0f);
                                this.scheduledButton.setScaleX(1.0f);
                            }
                        }
                        this.runningAnimation2.playTogether(animators);
                        this.runningAnimation2.setDuration(100L);
                        this.runningAnimation2.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.components.ChatActivityEnterView.24
                            @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                            public void onAnimationEnd(Animator animation) {
                                if (animation.equals(ChatActivityEnterView.this.runningAnimation2)) {
                                    ChatActivityEnterView.this.attachLayout.setVisibility(8);
                                    ChatActivityEnterView.this.runningAnimation2 = null;
                                }
                            }

                            @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                            public void onAnimationCancel(Animator animation) {
                                if (animation.equals(ChatActivityEnterView.this.runningAnimation2)) {
                                    ChatActivityEnterView.this.runningAnimation2 = null;
                                }
                            }
                        });
                        this.runningAnimation2.start();
                        updateFieldRight(0);
                    }
                    this.runningAnimationType = 5;
                    this.runningAnimation = new AnimatorSet();
                    ArrayList<Animator> animators2 = new ArrayList<>();
                    if (this.audioVideoButtonContainer.getVisibility() == 0) {
                        animators2.add(ObjectAnimator.ofFloat(this.audioVideoButtonContainer, (Property<FrameLayout, Float>) View.SCALE_X, 0.1f));
                        animators2.add(ObjectAnimator.ofFloat(this.audioVideoButtonContainer, (Property<FrameLayout, Float>) View.SCALE_Y, 0.1f));
                        animators2.add(ObjectAnimator.ofFloat(this.audioVideoButtonContainer, (Property<FrameLayout, Float>) View.ALPHA, 0.0f));
                    }
                    if (this.expandStickersButton.getVisibility() == 0) {
                        animators2.add(ObjectAnimator.ofFloat(this.expandStickersButton, (Property<ImageView, Float>) View.SCALE_X, 0.1f));
                        animators2.add(ObjectAnimator.ofFloat(this.expandStickersButton, (Property<ImageView, Float>) View.SCALE_Y, 0.1f));
                        animators2.add(ObjectAnimator.ofFloat(this.expandStickersButton, (Property<ImageView, Float>) View.ALPHA, 0.0f));
                    }
                    if (this.sendButton.getVisibility() == 0) {
                        animators2.add(ObjectAnimator.ofFloat(this.sendButton, (Property<View, Float>) View.SCALE_X, 0.1f));
                        animators2.add(ObjectAnimator.ofFloat(this.sendButton, (Property<View, Float>) View.SCALE_Y, 0.1f));
                        animators2.add(ObjectAnimator.ofFloat(this.sendButton, (Property<View, Float>) View.ALPHA, 0.0f));
                    }
                    if (this.cancelBotButton.getVisibility() == 0) {
                        animators2.add(ObjectAnimator.ofFloat(this.cancelBotButton, (Property<ImageView, Float>) View.SCALE_X, 0.1f));
                        animators2.add(ObjectAnimator.ofFloat(this.cancelBotButton, (Property<ImageView, Float>) View.SCALE_Y, 0.1f));
                        animators2.add(ObjectAnimator.ofFloat(this.cancelBotButton, (Property<ImageView, Float>) View.ALPHA, 0.0f));
                    }
                    animators2.add(ObjectAnimator.ofFloat(this.slowModeButton, (Property<SimpleTextView, Float>) View.SCALE_X, 1.0f));
                    animators2.add(ObjectAnimator.ofFloat(this.slowModeButton, (Property<SimpleTextView, Float>) View.SCALE_Y, 1.0f));
                    animators2.add(ObjectAnimator.ofFloat(this.slowModeButton, (Property<SimpleTextView, Float>) View.ALPHA, 1.0f));
                    this.slowModeButton.setVisibility(0);
                    this.runningAnimation.playTogether(animators2);
                    this.runningAnimation.setDuration(150L);
                    this.runningAnimation.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.components.ChatActivityEnterView.25
                        @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                        public void onAnimationEnd(Animator animation) {
                            if (animation.equals(ChatActivityEnterView.this.runningAnimation)) {
                                ChatActivityEnterView.this.sendButton.setVisibility(8);
                                ChatActivityEnterView.this.cancelBotButton.setVisibility(8);
                                ChatActivityEnterView.this.audioVideoButtonContainer.setVisibility(8);
                                ChatActivityEnterView.this.expandStickersButton.setVisibility(8);
                                ChatActivityEnterView.this.runningAnimation = null;
                                ChatActivityEnterView.this.runningAnimationType = 0;
                            }
                        }

                        @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                        public void onAnimationCancel(Animator animation) {
                            if (animation.equals(ChatActivityEnterView.this.runningAnimation)) {
                                ChatActivityEnterView.this.runningAnimation = null;
                            }
                        }
                    });
                    this.runningAnimation.start();
                    return;
                }
                this.slowModeButton.setScaleX(1.0f);
                this.slowModeButton.setScaleY(1.0f);
                this.slowModeButton.setAlpha(1.0f);
                this.slowModeButton.setVisibility(0);
                this.audioVideoButtonContainer.setScaleX(0.1f);
                this.audioVideoButtonContainer.setScaleY(0.1f);
                this.audioVideoButtonContainer.setAlpha(0.0f);
                this.audioVideoButtonContainer.setVisibility(8);
                this.sendButton.setScaleX(0.1f);
                this.sendButton.setScaleY(0.1f);
                this.sendButton.setAlpha(0.0f);
                this.sendButton.setVisibility(8);
                this.cancelBotButton.setScaleX(0.1f);
                this.cancelBotButton.setScaleY(0.1f);
                this.cancelBotButton.setAlpha(0.0f);
                this.cancelBotButton.setVisibility(8);
                if (this.expandStickersButton.getVisibility() != 0) {
                    i2 = 8;
                } else {
                    this.expandStickersButton.setScaleX(0.1f);
                    this.expandStickersButton.setScaleY(0.1f);
                    this.expandStickersButton.setAlpha(0.0f);
                    i2 = 8;
                    this.expandStickersButton.setVisibility(8);
                }
                LinearLayout linearLayout = this.attachLayout;
                if (linearLayout != null) {
                    linearLayout.setVisibility(i2);
                    updateFieldRight(0);
                }
                this.scheduleButtonHidden = false;
                if (this.scheduledButton != null) {
                    ChatActivityEnterViewDelegate chatActivityEnterViewDelegate2 = this.delegate;
                    if (chatActivityEnterViewDelegate2 != null && chatActivityEnterViewDelegate2.hasScheduledMessages()) {
                        this.scheduledButton.setVisibility(0);
                        this.scheduledButton.setTag(1);
                    }
                    ImageView imageView6 = this.scheduledButton;
                    ImageView imageView7 = this.botButton;
                    imageView6.setTranslationX(AndroidUtilities.dp((imageView7 == null || imageView7.getVisibility() != 0) ? 48.0f : 96.0f));
                    this.scheduledButton.setAlpha(1.0f);
                    this.scheduledButton.setScaleX(1.0f);
                    this.scheduledButton.setScaleY(1.0f);
                    return;
                }
                return;
            }
            return;
        }
        if (message.length() <= 0 && !this.forceShowSendButton && this.audioToSend == null && this.videoToSendMessageObject == null) {
            if (this.slowModeTimer != Integer.MAX_VALUE || isInScheduleMode()) {
                if (this.emojiView != null && this.emojiViewVisible && ((this.stickersTabOpen || (this.emojiTabOpen && this.searchingType == 2)) && !AndroidUtilities.isInMultiwindow)) {
                    if (animated2) {
                        if (this.runningAnimationType == 4) {
                            return;
                        }
                        AnimatorSet animatorSet3 = this.runningAnimation;
                        if (animatorSet3 != null) {
                            animatorSet3.cancel();
                            this.runningAnimation = null;
                        }
                        AnimatorSet animatorSet4 = this.runningAnimation2;
                        if (animatorSet4 != null) {
                            animatorSet4.cancel();
                            this.runningAnimation2 = null;
                        }
                        LinearLayout linearLayout2 = this.attachLayout;
                        if (linearLayout2 != null) {
                            linearLayout2.setVisibility(0);
                            this.runningAnimation2 = new AnimatorSet();
                            ArrayList<Animator> animators3 = new ArrayList<>();
                            animators3.add(ObjectAnimator.ofFloat(this.attachLayout, (Property<LinearLayout, Float>) View.ALPHA, 1.0f));
                            animators3.add(ObjectAnimator.ofFloat(this.attachLayout, (Property<LinearLayout, Float>) View.SCALE_X, 1.0f));
                            ChatActivityEnterViewDelegate chatActivityEnterViewDelegate3 = this.delegate;
                            boolean hasScheduled2 = chatActivityEnterViewDelegate3 != null && chatActivityEnterViewDelegate3.hasScheduledMessages();
                            this.scheduleButtonHidden = false;
                            ImageView imageView8 = this.scheduledButton;
                            if (imageView8 != null) {
                                imageView8.setScaleY(1.0f);
                                if (hasScheduled2) {
                                    this.scheduledButton.setVisibility(0);
                                    this.scheduledButton.setTag(1);
                                    this.scheduledButton.setPivotX(AndroidUtilities.dp(48.0f));
                                    animators3.add(ObjectAnimator.ofFloat(this.scheduledButton, (Property<ImageView, Float>) View.ALPHA, 1.0f));
                                    animators3.add(ObjectAnimator.ofFloat(this.scheduledButton, (Property<ImageView, Float>) View.SCALE_X, 1.0f));
                                    animators3.add(ObjectAnimator.ofFloat(this.scheduledButton, (Property<ImageView, Float>) View.TRANSLATION_X, 0.0f));
                                } else {
                                    this.scheduledButton.setAlpha(1.0f);
                                    this.scheduledButton.setScaleX(1.0f);
                                    this.scheduledButton.setTranslationX(0.0f);
                                }
                            }
                            this.runningAnimation2.playTogether(animators3);
                            this.runningAnimation2.setDuration(100L);
                            this.runningAnimation2.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.components.ChatActivityEnterView.28
                                @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                                public void onAnimationEnd(Animator animation) {
                                    if (animation.equals(ChatActivityEnterView.this.runningAnimation2)) {
                                        ChatActivityEnterView.this.runningAnimation2 = null;
                                    }
                                }

                                @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                                public void onAnimationCancel(Animator animation) {
                                    if (animation.equals(ChatActivityEnterView.this.runningAnimation2)) {
                                        ChatActivityEnterView.this.runningAnimation2 = null;
                                    }
                                }
                            });
                            this.runningAnimation2.start();
                            updateFieldRight(1);
                            if (getVisibility() == 0) {
                                this.delegate.onAttachButtonShow();
                            }
                        }
                        this.expandStickersButton.setVisibility(0);
                        this.runningAnimation = new AnimatorSet();
                        this.runningAnimationType = 4;
                        ArrayList<Animator> animators4 = new ArrayList<>();
                        animators4.add(ObjectAnimator.ofFloat(this.expandStickersButton, (Property<ImageView, Float>) View.SCALE_X, 1.0f));
                        animators4.add(ObjectAnimator.ofFloat(this.expandStickersButton, (Property<ImageView, Float>) View.SCALE_Y, 1.0f));
                        animators4.add(ObjectAnimator.ofFloat(this.expandStickersButton, (Property<ImageView, Float>) View.ALPHA, 1.0f));
                        if (this.cancelBotButton.getVisibility() == 0) {
                            animators4.add(ObjectAnimator.ofFloat(this.cancelBotButton, (Property<ImageView, Float>) View.SCALE_X, 0.1f));
                            animators4.add(ObjectAnimator.ofFloat(this.cancelBotButton, (Property<ImageView, Float>) View.SCALE_Y, 0.1f));
                            animators4.add(ObjectAnimator.ofFloat(this.cancelBotButton, (Property<ImageView, Float>) View.ALPHA, 0.0f));
                        } else if (this.audioVideoButtonContainer.getVisibility() == 0) {
                            animators4.add(ObjectAnimator.ofFloat(this.audioVideoButtonContainer, (Property<FrameLayout, Float>) View.SCALE_X, 0.1f));
                            animators4.add(ObjectAnimator.ofFloat(this.audioVideoButtonContainer, (Property<FrameLayout, Float>) View.SCALE_Y, 0.1f));
                            animators4.add(ObjectAnimator.ofFloat(this.audioVideoButtonContainer, (Property<FrameLayout, Float>) View.ALPHA, 0.0f));
                        } else if (this.slowModeButton.getVisibility() == 0) {
                            animators4.add(ObjectAnimator.ofFloat(this.slowModeButton, (Property<SimpleTextView, Float>) View.SCALE_X, 0.1f));
                            animators4.add(ObjectAnimator.ofFloat(this.slowModeButton, (Property<SimpleTextView, Float>) View.SCALE_Y, 0.1f));
                            animators4.add(ObjectAnimator.ofFloat(this.slowModeButton, (Property<SimpleTextView, Float>) View.ALPHA, 0.0f));
                        } else {
                            animators4.add(ObjectAnimator.ofFloat(this.sendButton, (Property<View, Float>) View.SCALE_X, 0.1f));
                            animators4.add(ObjectAnimator.ofFloat(this.sendButton, (Property<View, Float>) View.SCALE_Y, 0.1f));
                            animators4.add(ObjectAnimator.ofFloat(this.sendButton, (Property<View, Float>) View.ALPHA, 0.0f));
                        }
                        this.runningAnimation.playTogether(animators4);
                        this.runningAnimation.setDuration(150L);
                        this.runningAnimation.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.components.ChatActivityEnterView.29
                            @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                            public void onAnimationEnd(Animator animation) {
                                if (animation.equals(ChatActivityEnterView.this.runningAnimation)) {
                                    ChatActivityEnterView.this.sendButton.setVisibility(8);
                                    ChatActivityEnterView.this.cancelBotButton.setVisibility(8);
                                    ChatActivityEnterView.this.slowModeButton.setVisibility(8);
                                    ChatActivityEnterView.this.audioVideoButtonContainer.setVisibility(8);
                                    ChatActivityEnterView.this.expandStickersButton.setVisibility(0);
                                    ChatActivityEnterView.this.runningAnimation = null;
                                    ChatActivityEnterView.this.runningAnimationType = 0;
                                }
                            }

                            @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                            public void onAnimationCancel(Animator animation) {
                                if (animation.equals(ChatActivityEnterView.this.runningAnimation)) {
                                    ChatActivityEnterView.this.runningAnimation = null;
                                }
                            }
                        });
                        this.runningAnimation.start();
                        return;
                    }
                    this.slowModeButton.setScaleX(0.1f);
                    this.slowModeButton.setScaleY(0.1f);
                    this.slowModeButton.setAlpha(0.0f);
                    this.slowModeButton.setVisibility(8);
                    this.sendButton.setScaleX(0.1f);
                    this.sendButton.setScaleY(0.1f);
                    this.sendButton.setAlpha(0.0f);
                    this.sendButton.setVisibility(8);
                    this.cancelBotButton.setScaleX(0.1f);
                    this.cancelBotButton.setScaleY(0.1f);
                    this.cancelBotButton.setAlpha(0.0f);
                    this.cancelBotButton.setVisibility(8);
                    this.audioVideoButtonContainer.setScaleX(0.1f);
                    this.audioVideoButtonContainer.setScaleY(0.1f);
                    this.audioVideoButtonContainer.setAlpha(0.0f);
                    this.audioVideoButtonContainer.setVisibility(8);
                    this.expandStickersButton.setScaleX(1.0f);
                    this.expandStickersButton.setScaleY(1.0f);
                    this.expandStickersButton.setAlpha(1.0f);
                    this.expandStickersButton.setVisibility(0);
                    if (this.attachLayout != null) {
                        if (getVisibility() == 0) {
                            this.delegate.onAttachButtonShow();
                        }
                        this.attachLayout.setVisibility(0);
                        updateFieldRight(1);
                    }
                    this.scheduleButtonHidden = false;
                    if (this.scheduledButton != null) {
                        ChatActivityEnterViewDelegate chatActivityEnterViewDelegate4 = this.delegate;
                        if (chatActivityEnterViewDelegate4 != null && chatActivityEnterViewDelegate4.hasScheduledMessages()) {
                            this.scheduledButton.setVisibility(0);
                            this.scheduledButton.setTag(1);
                        }
                        this.scheduledButton.setAlpha(1.0f);
                        this.scheduledButton.setScaleX(1.0f);
                        this.scheduledButton.setScaleY(1.0f);
                        this.scheduledButton.setTranslationX(0.0f);
                        return;
                    }
                    return;
                }
                if (this.sendButton.getVisibility() == 0 || this.cancelBotButton.getVisibility() == 0 || this.expandStickersButton.getVisibility() == 0 || this.slowModeButton.getVisibility() == 0) {
                    if (animated2) {
                        if (this.runningAnimationType == 2) {
                            return;
                        }
                        AnimatorSet animatorSet5 = this.runningAnimation;
                        if (animatorSet5 != null) {
                            animatorSet5.cancel();
                            this.runningAnimation = null;
                        }
                        AnimatorSet animatorSet6 = this.runningAnimation2;
                        if (animatorSet6 != null) {
                            animatorSet6.cancel();
                            this.runningAnimation2 = null;
                        }
                        LinearLayout linearLayout3 = this.attachLayout;
                        if (linearLayout3 != null) {
                            linearLayout3.setVisibility(0);
                            this.runningAnimation2 = new AnimatorSet();
                            ArrayList<Animator> animators5 = new ArrayList<>();
                            animators5.add(ObjectAnimator.ofFloat(this.attachLayout, (Property<LinearLayout, Float>) View.ALPHA, 1.0f));
                            animators5.add(ObjectAnimator.ofFloat(this.attachLayout, (Property<LinearLayout, Float>) View.SCALE_X, 1.0f));
                            ChatActivityEnterViewDelegate chatActivityEnterViewDelegate5 = this.delegate;
                            boolean hasScheduled3 = chatActivityEnterViewDelegate5 != null && chatActivityEnterViewDelegate5.hasScheduledMessages();
                            this.scheduleButtonHidden = false;
                            ImageView imageView9 = this.scheduledButton;
                            if (imageView9 != null) {
                                if (hasScheduled3) {
                                    imageView9.setVisibility(0);
                                    this.scheduledButton.setTag(1);
                                    this.scheduledButton.setPivotX(AndroidUtilities.dp(48.0f));
                                    animators5.add(ObjectAnimator.ofFloat(this.scheduledButton, (Property<ImageView, Float>) View.ALPHA, 1.0f));
                                    animators5.add(ObjectAnimator.ofFloat(this.scheduledButton, (Property<ImageView, Float>) View.SCALE_X, 1.0f));
                                    animators5.add(ObjectAnimator.ofFloat(this.scheduledButton, (Property<ImageView, Float>) View.TRANSLATION_X, 0.0f));
                                } else {
                                    imageView9.setAlpha(1.0f);
                                    this.scheduledButton.setScaleX(1.0f);
                                    this.scheduledButton.setScaleY(1.0f);
                                    this.scheduledButton.setTranslationX(0.0f);
                                }
                            }
                            this.runningAnimation2.playTogether(animators5);
                            this.runningAnimation2.setDuration(100L);
                            this.runningAnimation2.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.components.ChatActivityEnterView.30
                                @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                                public void onAnimationEnd(Animator animation) {
                                    if (animation.equals(ChatActivityEnterView.this.runningAnimation2)) {
                                        ChatActivityEnterView.this.runningAnimation2 = null;
                                    }
                                }

                                @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                                public void onAnimationCancel(Animator animation) {
                                    if (animation.equals(ChatActivityEnterView.this.runningAnimation2)) {
                                        ChatActivityEnterView.this.runningAnimation2 = null;
                                    }
                                }
                            });
                            this.runningAnimation2.start();
                            updateFieldRight(1);
                            if (getVisibility() == 0) {
                                this.delegate.onAttachButtonShow();
                            }
                        }
                        this.audioVideoButtonContainer.setVisibility(0);
                        this.runningAnimation = new AnimatorSet();
                        this.runningAnimationType = 2;
                        ArrayList<Animator> animators6 = new ArrayList<>();
                        animators6.add(ObjectAnimator.ofFloat(this.audioVideoButtonContainer, (Property<FrameLayout, Float>) View.SCALE_X, 1.0f));
                        animators6.add(ObjectAnimator.ofFloat(this.audioVideoButtonContainer, (Property<FrameLayout, Float>) View.SCALE_Y, 1.0f));
                        animators6.add(ObjectAnimator.ofFloat(this.audioVideoButtonContainer, (Property<FrameLayout, Float>) View.ALPHA, 1.0f));
                        if (this.cancelBotButton.getVisibility() == 0) {
                            animators6.add(ObjectAnimator.ofFloat(this.cancelBotButton, (Property<ImageView, Float>) View.SCALE_X, 0.1f));
                            animators6.add(ObjectAnimator.ofFloat(this.cancelBotButton, (Property<ImageView, Float>) View.SCALE_Y, 0.1f));
                            animators6.add(ObjectAnimator.ofFloat(this.cancelBotButton, (Property<ImageView, Float>) View.ALPHA, 0.0f));
                        } else if (this.expandStickersButton.getVisibility() == 0) {
                            animators6.add(ObjectAnimator.ofFloat(this.expandStickersButton, (Property<ImageView, Float>) View.SCALE_X, 0.1f));
                            animators6.add(ObjectAnimator.ofFloat(this.expandStickersButton, (Property<ImageView, Float>) View.SCALE_Y, 0.1f));
                            animators6.add(ObjectAnimator.ofFloat(this.expandStickersButton, (Property<ImageView, Float>) View.ALPHA, 0.0f));
                        } else if (this.slowModeButton.getVisibility() == 0) {
                            animators6.add(ObjectAnimator.ofFloat(this.slowModeButton, (Property<SimpleTextView, Float>) View.SCALE_X, 0.1f));
                            animators6.add(ObjectAnimator.ofFloat(this.slowModeButton, (Property<SimpleTextView, Float>) View.SCALE_Y, 0.1f));
                            animators6.add(ObjectAnimator.ofFloat(this.slowModeButton, (Property<SimpleTextView, Float>) View.ALPHA, 0.0f));
                        } else {
                            animators6.add(ObjectAnimator.ofFloat(this.sendButton, (Property<View, Float>) View.SCALE_X, 0.1f));
                            animators6.add(ObjectAnimator.ofFloat(this.sendButton, (Property<View, Float>) View.SCALE_Y, 0.1f));
                            animators6.add(ObjectAnimator.ofFloat(this.sendButton, (Property<View, Float>) View.ALPHA, 0.0f));
                        }
                        this.runningAnimation.playTogether(animators6);
                        this.runningAnimation.setDuration(150L);
                        this.runningAnimation.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.components.ChatActivityEnterView.31
                            @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                            public void onAnimationEnd(Animator animation) {
                                if (animation.equals(ChatActivityEnterView.this.runningAnimation)) {
                                    ChatActivityEnterView.this.sendButton.setVisibility(8);
                                    ChatActivityEnterView.this.cancelBotButton.setVisibility(8);
                                    ChatActivityEnterView.this.slowModeButton.setVisibility(8);
                                    ChatActivityEnterView.this.audioVideoButtonContainer.setVisibility(0);
                                    ChatActivityEnterView.this.runningAnimation = null;
                                    ChatActivityEnterView.this.runningAnimationType = 0;
                                }
                            }

                            @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                            public void onAnimationCancel(Animator animation) {
                                if (animation.equals(ChatActivityEnterView.this.runningAnimation)) {
                                    ChatActivityEnterView.this.runningAnimation = null;
                                }
                            }
                        });
                        this.runningAnimation.start();
                        return;
                    }
                    this.slowModeButton.setScaleX(0.1f);
                    this.slowModeButton.setScaleY(0.1f);
                    this.slowModeButton.setAlpha(0.0f);
                    this.slowModeButton.setVisibility(8);
                    this.sendButton.setScaleX(0.1f);
                    this.sendButton.setScaleY(0.1f);
                    this.sendButton.setAlpha(0.0f);
                    this.sendButton.setVisibility(8);
                    this.cancelBotButton.setScaleX(0.1f);
                    this.cancelBotButton.setScaleY(0.1f);
                    this.cancelBotButton.setAlpha(0.0f);
                    this.cancelBotButton.setVisibility(8);
                    this.expandStickersButton.setScaleX(0.1f);
                    this.expandStickersButton.setScaleY(0.1f);
                    this.expandStickersButton.setAlpha(0.0f);
                    this.expandStickersButton.setVisibility(8);
                    this.audioVideoButtonContainer.setScaleX(1.0f);
                    this.audioVideoButtonContainer.setScaleY(1.0f);
                    this.audioVideoButtonContainer.setAlpha(1.0f);
                    this.audioVideoButtonContainer.setVisibility(0);
                    if (this.attachLayout != null) {
                        if (getVisibility() == 0) {
                            this.delegate.onAttachButtonShow();
                        }
                        this.attachLayout.setAlpha(1.0f);
                        this.attachLayout.setScaleX(1.0f);
                        this.attachLayout.setVisibility(0);
                        updateFieldRight(1);
                    }
                    this.scheduleButtonHidden = false;
                    if (this.scheduledButton != null) {
                        ChatActivityEnterViewDelegate chatActivityEnterViewDelegate6 = this.delegate;
                        if (chatActivityEnterViewDelegate6 != null && chatActivityEnterViewDelegate6.hasScheduledMessages()) {
                            this.scheduledButton.setVisibility(0);
                            this.scheduledButton.setTag(1);
                        }
                        this.scheduledButton.setAlpha(1.0f);
                        this.scheduledButton.setScaleX(1.0f);
                        this.scheduledButton.setScaleY(1.0f);
                        this.scheduledButton.setTranslationX(0.0f);
                        return;
                    }
                    return;
                }
                return;
            }
        }
        final String caption = this.messageEditText.getCaption();
        boolean showBotButton = caption != null && (this.sendButton.getVisibility() == 0 || this.expandStickersButton.getVisibility() == 0);
        boolean showSendButton = caption == null && (this.cancelBotButton.getVisibility() == 0 || this.expandStickersButton.getVisibility() == 0);
        if (this.slowModeTimer == Integer.MAX_VALUE && !isInScheduleMode()) {
            color = Theme.getColor(Theme.key_chat_messagePanelIcons);
        } else {
            color = Theme.getColor(Theme.key_chat_messagePanelSend);
        }
        Theme.setSelectorDrawableColor(this.sendButton.getBackground(), Color.argb(24, Color.red(color), Color.green(color), Color.blue(color)), true);
        if (this.audioVideoButtonContainer.getVisibility() == 0 || this.slowModeButton.getVisibility() == 0 || showBotButton || showSendButton) {
            if (animated2) {
                if (this.runningAnimationType != 1 || this.messageEditText.getCaption() != null) {
                    if (this.runningAnimationType == 3 && caption != null) {
                        return;
                    }
                    AnimatorSet animatorSet7 = this.runningAnimation;
                    if (animatorSet7 != null) {
                        animatorSet7.cancel();
                        this.runningAnimation = null;
                    }
                    AnimatorSet animatorSet8 = this.runningAnimation2;
                    if (animatorSet8 != null) {
                        animatorSet8.cancel();
                        this.runningAnimation2 = null;
                    }
                    if (this.attachLayout != null) {
                        this.runningAnimation2 = new AnimatorSet();
                        ArrayList<Animator> animators7 = new ArrayList<>();
                        animators7.add(ObjectAnimator.ofFloat(this.attachLayout, (Property<LinearLayout, Float>) View.ALPHA, 0.0f));
                        animators7.add(ObjectAnimator.ofFloat(this.attachLayout, (Property<LinearLayout, Float>) View.SCALE_X, 0.0f));
                        ChatActivityEnterViewDelegate chatActivityEnterViewDelegate7 = this.delegate;
                        final boolean hasScheduled4 = chatActivityEnterViewDelegate7 != null && chatActivityEnterViewDelegate7.hasScheduledMessages();
                        this.scheduleButtonHidden = true;
                        ImageView imageView10 = this.scheduledButton;
                        if (imageView10 != null) {
                            imageView10.setScaleY(1.0f);
                            if (hasScheduled4) {
                                this.scheduledButton.setTag(null);
                                animators7.add(ObjectAnimator.ofFloat(this.scheduledButton, (Property<ImageView, Float>) View.ALPHA, 0.0f));
                                animators7.add(ObjectAnimator.ofFloat(this.scheduledButton, (Property<ImageView, Float>) View.SCALE_X, 0.0f));
                                ImageView imageView11 = this.scheduledButton;
                                Property property2 = View.TRANSLATION_X;
                                float[] fArr2 = new float[1];
                                ImageView imageView12 = this.botButton;
                                fArr2[0] = AndroidUtilities.dp((imageView12 == null || imageView12.getVisibility() == 8) ? 48.0f : 96.0f);
                                animators7.add(ObjectAnimator.ofFloat(imageView11, (Property<ImageView, Float>) property2, fArr2));
                            } else {
                                this.scheduledButton.setAlpha(0.0f);
                                this.scheduledButton.setScaleX(0.0f);
                                ImageView imageView13 = this.scheduledButton;
                                ImageView imageView14 = this.botButton;
                                imageView13.setTranslationX(AndroidUtilities.dp((imageView14 == null || imageView14.getVisibility() == 8) ? 48.0f : 96.0f));
                            }
                        }
                        this.runningAnimation2.playTogether(animators7);
                        this.runningAnimation2.setDuration(100L);
                        this.runningAnimation2.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.components.ChatActivityEnterView.26
                            @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                            public void onAnimationEnd(Animator animation) {
                                if (animation.equals(ChatActivityEnterView.this.runningAnimation2)) {
                                    ChatActivityEnterView.this.attachLayout.setVisibility(8);
                                    if (hasScheduled4) {
                                        ChatActivityEnterView.this.scheduledButton.setVisibility(8);
                                    }
                                    ChatActivityEnterView.this.runningAnimation2 = null;
                                }
                            }

                            @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                            public void onAnimationCancel(Animator animation) {
                                if (animation.equals(ChatActivityEnterView.this.runningAnimation2)) {
                                    ChatActivityEnterView.this.runningAnimation2 = null;
                                }
                            }
                        });
                        this.runningAnimation2.start();
                        updateFieldRight(0);
                        if (this.delegate != null && getVisibility() == 0) {
                            this.delegate.onAttachButtonHidden();
                        }
                    }
                    this.runningAnimation = new AnimatorSet();
                    ArrayList<Animator> animators8 = new ArrayList<>();
                    if (this.audioVideoButtonContainer.getVisibility() == 0) {
                        animators8.add(ObjectAnimator.ofFloat(this.audioVideoButtonContainer, (Property<FrameLayout, Float>) View.SCALE_X, 0.1f));
                        animators8.add(ObjectAnimator.ofFloat(this.audioVideoButtonContainer, (Property<FrameLayout, Float>) View.SCALE_Y, 0.1f));
                        animators8.add(ObjectAnimator.ofFloat(this.audioVideoButtonContainer, (Property<FrameLayout, Float>) View.ALPHA, 0.0f));
                    }
                    if (this.expandStickersButton.getVisibility() == 0) {
                        animators8.add(ObjectAnimator.ofFloat(this.expandStickersButton, (Property<ImageView, Float>) View.SCALE_X, 0.1f));
                        animators8.add(ObjectAnimator.ofFloat(this.expandStickersButton, (Property<ImageView, Float>) View.SCALE_Y, 0.1f));
                        animators8.add(ObjectAnimator.ofFloat(this.expandStickersButton, (Property<ImageView, Float>) View.ALPHA, 0.0f));
                    }
                    if (this.slowModeButton.getVisibility() == 0) {
                        animators8.add(ObjectAnimator.ofFloat(this.slowModeButton, (Property<SimpleTextView, Float>) View.SCALE_X, 0.1f));
                        animators8.add(ObjectAnimator.ofFloat(this.slowModeButton, (Property<SimpleTextView, Float>) View.SCALE_Y, 0.1f));
                        animators8.add(ObjectAnimator.ofFloat(this.slowModeButton, (Property<SimpleTextView, Float>) View.ALPHA, 0.0f));
                    }
                    if (showBotButton) {
                        animators8.add(ObjectAnimator.ofFloat(this.sendButton, (Property<View, Float>) View.SCALE_X, 0.1f));
                        animators8.add(ObjectAnimator.ofFloat(this.sendButton, (Property<View, Float>) View.SCALE_Y, 0.1f));
                        animators8.add(ObjectAnimator.ofFloat(this.sendButton, (Property<View, Float>) View.ALPHA, 0.0f));
                    } else if (showSendButton) {
                        animators8.add(ObjectAnimator.ofFloat(this.cancelBotButton, (Property<ImageView, Float>) View.SCALE_X, 0.1f));
                        animators8.add(ObjectAnimator.ofFloat(this.cancelBotButton, (Property<ImageView, Float>) View.SCALE_Y, 0.1f));
                        animators8.add(ObjectAnimator.ofFloat(this.cancelBotButton, (Property<ImageView, Float>) View.ALPHA, 0.0f));
                    }
                    if (caption != null) {
                        this.runningAnimationType = 3;
                        animators8.add(ObjectAnimator.ofFloat(this.cancelBotButton, (Property<ImageView, Float>) View.SCALE_X, 1.0f));
                        animators8.add(ObjectAnimator.ofFloat(this.cancelBotButton, (Property<ImageView, Float>) View.SCALE_Y, 1.0f));
                        animators8.add(ObjectAnimator.ofFloat(this.cancelBotButton, (Property<ImageView, Float>) View.ALPHA, 1.0f));
                        this.cancelBotButton.setVisibility(0);
                    } else {
                        this.runningAnimationType = 1;
                        animators8.add(ObjectAnimator.ofFloat(this.sendButton, (Property<View, Float>) View.SCALE_X, 1.0f));
                        animators8.add(ObjectAnimator.ofFloat(this.sendButton, (Property<View, Float>) View.SCALE_Y, 1.0f));
                        animators8.add(ObjectAnimator.ofFloat(this.sendButton, (Property<View, Float>) View.ALPHA, 1.0f));
                        this.sendButton.setVisibility(0);
                    }
                    this.runningAnimation.playTogether(animators8);
                    this.runningAnimation.setDuration(150L);
                    this.runningAnimation.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.components.ChatActivityEnterView.27
                        @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                        public void onAnimationEnd(Animator animation) {
                            if (animation.equals(ChatActivityEnterView.this.runningAnimation)) {
                                if (caption != null) {
                                    ChatActivityEnterView.this.cancelBotButton.setVisibility(0);
                                    ChatActivityEnterView.this.sendButton.setVisibility(8);
                                } else {
                                    ChatActivityEnterView.this.sendButton.setVisibility(0);
                                    ChatActivityEnterView.this.cancelBotButton.setVisibility(8);
                                }
                                ChatActivityEnterView.this.audioVideoButtonContainer.setVisibility(8);
                                ChatActivityEnterView.this.expandStickersButton.setVisibility(8);
                                ChatActivityEnterView.this.slowModeButton.setVisibility(8);
                                ChatActivityEnterView.this.runningAnimation = null;
                                ChatActivityEnterView.this.runningAnimationType = 0;
                            }
                        }

                        @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                        public void onAnimationCancel(Animator animation) {
                            if (animation.equals(ChatActivityEnterView.this.runningAnimation)) {
                                ChatActivityEnterView.this.runningAnimation = null;
                            }
                        }
                    });
                    this.runningAnimation.start();
                    return;
                }
                return;
            }
            this.audioVideoButtonContainer.setScaleX(0.1f);
            this.audioVideoButtonContainer.setScaleY(0.1f);
            this.audioVideoButtonContainer.setAlpha(0.0f);
            this.audioVideoButtonContainer.setVisibility(8);
            if (this.slowModeButton.getVisibility() == 0) {
                this.slowModeButton.setScaleX(0.1f);
                this.slowModeButton.setScaleY(0.1f);
                this.slowModeButton.setAlpha(0.0f);
                this.slowModeButton.setVisibility(8);
            }
            if (caption != null) {
                this.sendButton.setScaleX(0.1f);
                this.sendButton.setScaleY(0.1f);
                this.sendButton.setAlpha(0.0f);
                this.sendButton.setVisibility(8);
                this.cancelBotButton.setScaleX(1.0f);
                this.cancelBotButton.setScaleY(1.0f);
                this.cancelBotButton.setAlpha(1.0f);
                this.cancelBotButton.setVisibility(0);
            } else {
                this.cancelBotButton.setScaleX(0.1f);
                this.cancelBotButton.setScaleY(0.1f);
                this.cancelBotButton.setAlpha(0.0f);
                this.sendButton.setVisibility(0);
                this.sendButton.setScaleX(1.0f);
                this.sendButton.setScaleY(1.0f);
                this.sendButton.setAlpha(1.0f);
                this.cancelBotButton.setVisibility(8);
            }
            if (this.expandStickersButton.getVisibility() != 0) {
                i = 8;
            } else {
                this.expandStickersButton.setScaleX(0.1f);
                this.expandStickersButton.setScaleY(0.1f);
                this.expandStickersButton.setAlpha(0.0f);
                i = 8;
                this.expandStickersButton.setVisibility(8);
            }
            LinearLayout linearLayout4 = this.attachLayout;
            if (linearLayout4 != null) {
                linearLayout4.setVisibility(i);
                if (this.delegate != null && getVisibility() == 0) {
                    this.delegate.onAttachButtonHidden();
                }
                updateFieldRight(0);
            }
            this.scheduleButtonHidden = true;
            if (this.scheduledButton != null) {
                ChatActivityEnterViewDelegate chatActivityEnterViewDelegate8 = this.delegate;
                if (chatActivityEnterViewDelegate8 != null && chatActivityEnterViewDelegate8.hasScheduledMessages()) {
                    this.scheduledButton.setVisibility(8);
                    this.scheduledButton.setTag(null);
                }
                this.scheduledButton.setAlpha(0.0f);
                this.scheduledButton.setScaleX(0.0f);
                this.scheduledButton.setScaleY(1.0f);
                ImageView imageView15 = this.scheduledButton;
                ImageView imageView16 = this.botButton;
                imageView15.setTranslationX(AndroidUtilities.dp((imageView16 == null || imageView16.getVisibility() == 8) ? 48.0f : 96.0f));
            }
        }
    }

    private void updateFieldRight(int attachVisible) {
        ImageView imageView;
        ImageView imageView2;
        ImageView imageView3;
        ImageView imageView4;
        EditTextCaption editTextCaption = this.messageEditText;
        if (editTextCaption == null || this.editingMessageObject != null) {
            return;
        }
        FrameLayout.LayoutParams layoutParams = (FrameLayout.LayoutParams) editTextCaption.getLayoutParams();
        if (attachVisible == 1) {
            ImageView imageView5 = this.botButton;
            if ((imageView5 != null && imageView5.getVisibility() == 0) || (((imageView3 = this.notifyButton) != null && imageView3.getVisibility() == 0) || ((imageView4 = this.scheduledButton) != null && imageView4.getTag() != null))) {
                layoutParams.rightMargin = AndroidUtilities.dp(98.0f);
            } else {
                layoutParams.rightMargin = AndroidUtilities.dp(50.0f);
            }
        } else if (attachVisible == 2) {
            if (layoutParams.rightMargin != AndroidUtilities.dp(2.0f)) {
                ImageView imageView6 = this.botButton;
                if ((imageView6 != null && imageView6.getVisibility() == 0) || (((imageView = this.notifyButton) != null && imageView.getVisibility() == 0) || ((imageView2 = this.scheduledButton) != null && imageView2.getTag() != null))) {
                    layoutParams.rightMargin = AndroidUtilities.dp(98.0f);
                } else {
                    layoutParams.rightMargin = AndroidUtilities.dp(50.0f);
                }
            }
        } else {
            ImageView imageView7 = this.scheduledButton;
            if (imageView7 != null && imageView7.getTag() != null) {
                layoutParams.rightMargin = AndroidUtilities.dp(50.0f);
            } else {
                layoutParams.rightMargin = AndroidUtilities.dp(2.0f);
            }
        }
        this.messageEditText.setLayoutParams(layoutParams);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void updateRecordIntefrace() {
        if (this.recordingAudioVideo) {
            if (this.recordInterfaceState == 1) {
                return;
            }
            this.recordInterfaceState = 1;
            try {
                if (this.wakeLock == null) {
                    PowerManager pm = (PowerManager) ApplicationLoader.applicationContext.getSystemService("power");
                    PowerManager.WakeLock wakeLockNewWakeLock = pm.newWakeLock(536870918, "hchat:audio_record_lock");
                    this.wakeLock = wakeLockNewWakeLock;
                    wakeLockNewWakeLock.acquire();
                }
            } catch (Exception e) {
                FileLog.e(e);
            }
            AndroidUtilities.lockOrientation(this.parentActivity);
            ChatActivityEnterViewDelegate chatActivityEnterViewDelegate = this.delegate;
            if (chatActivityEnterViewDelegate != null) {
                chatActivityEnterViewDelegate.needStartRecordAudio(0);
            }
            this.recordPanel.setVisibility(0);
            this.recordCircle.setVisibility(0);
            this.recordCircle.setAmplitude(FirebaseRemoteConfig.DEFAULT_VALUE_FOR_DOUBLE);
            this.recordTimeText.setText(String.format("%02d:%02d.%02d", 0, 0, 0));
            this.recordDot.resetAlpha();
            this.lastTimeString = null;
            this.lastTypingSendTime = -1L;
            FrameLayout.LayoutParams params = (FrameLayout.LayoutParams) this.slideText.getLayoutParams();
            params.leftMargin = AndroidUtilities.dp(30.0f);
            this.slideText.setLayoutParams(params);
            this.slideText.setAlpha(1.0f);
            this.recordPanel.setX(AndroidUtilities.displaySize.x);
            AnimatorSet animatorSet = this.runningAnimationAudio;
            if (animatorSet != null) {
                animatorSet.cancel();
            }
            AnimatorSet animatorSet2 = new AnimatorSet();
            this.runningAnimationAudio = animatorSet2;
            animatorSet2.playTogether(ObjectAnimator.ofFloat(this.recordPanel, (Property<FrameLayout, Float>) View.TRANSLATION_X, 0.0f), ObjectAnimator.ofFloat(this.recordCircle, this.recordCircleScale, 1.0f), ObjectAnimator.ofFloat(this.audioVideoButtonContainer, (Property<FrameLayout, Float>) View.ALPHA, 0.0f));
            this.runningAnimationAudio.setDuration(300L);
            this.runningAnimationAudio.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.components.ChatActivityEnterView.32
                @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                public void onAnimationEnd(Animator animator) {
                    if (animator.equals(ChatActivityEnterView.this.runningAnimationAudio)) {
                        ChatActivityEnterView.this.recordPanel.setX(0.0f);
                        ChatActivityEnterView.this.runningAnimationAudio = null;
                    }
                }
            });
            this.runningAnimationAudio.setInterpolator(new DecelerateInterpolator());
            this.runningAnimationAudio.start();
            return;
        }
        PowerManager.WakeLock wakeLock = this.wakeLock;
        if (wakeLock != null) {
            try {
                wakeLock.release();
                this.wakeLock = null;
            } catch (Exception e2) {
                FileLog.e(e2);
            }
        }
        AndroidUtilities.unlockOrientation(this.parentActivity);
        if (this.recordInterfaceState == 0) {
            return;
        }
        this.recordInterfaceState = 0;
        AnimatorSet animatorSet3 = this.runningAnimationAudio;
        if (animatorSet3 != null) {
            animatorSet3.cancel();
        }
        AnimatorSet animatorSet4 = new AnimatorSet();
        this.runningAnimationAudio = animatorSet4;
        animatorSet4.playTogether(ObjectAnimator.ofFloat(this.recordPanel, (Property<FrameLayout, Float>) View.TRANSLATION_X, AndroidUtilities.displaySize.x), ObjectAnimator.ofFloat(this.recordCircle, this.recordCircleScale, 0.0f), ObjectAnimator.ofFloat(this.audioVideoButtonContainer, (Property<FrameLayout, Float>) View.ALPHA, 1.0f));
        this.runningAnimationAudio.setDuration(300L);
        this.runningAnimationAudio.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.components.ChatActivityEnterView.33
            @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
            public void onAnimationEnd(Animator animator) {
                if (animator.equals(ChatActivityEnterView.this.runningAnimationAudio)) {
                    FrameLayout.LayoutParams params2 = (FrameLayout.LayoutParams) ChatActivityEnterView.this.slideText.getLayoutParams();
                    params2.leftMargin = AndroidUtilities.dp(30.0f);
                    ChatActivityEnterView.this.slideText.setLayoutParams(params2);
                    ChatActivityEnterView.this.slideText.setAlpha(1.0f);
                    ChatActivityEnterView.this.recordPanel.setVisibility(8);
                    ChatActivityEnterView.this.recordCircle.setVisibility(8);
                    ChatActivityEnterView.this.recordCircle.setSendButtonInvisible();
                    ChatActivityEnterView.this.runningAnimationAudio = null;
                }
            }
        });
        this.runningAnimationAudio.setInterpolator(new AccelerateInterpolator());
        this.runningAnimationAudio.start();
    }

    @Override // android.view.ViewGroup
    public boolean onInterceptTouchEvent(MotionEvent ev) {
        if (this.recordingAudioVideo) {
            getParent().requestDisallowInterceptTouchEvent(true);
        }
        return super.onInterceptTouchEvent(ev);
    }

    public void setDelegate(ChatActivityEnterViewDelegate chatActivityEnterViewDelegate) {
        this.delegate = chatActivityEnterViewDelegate;
    }

    public void setCommand(MessageObject messageObject, String command, boolean longPress, boolean username) {
        String text;
        if (command == null || getVisibility() != 0) {
            return;
        }
        TLRPC.User user = null;
        if (longPress) {
            String text2 = this.messageEditText.getText().toString();
            if (messageObject != null && ((int) this.dialog_id) < 0) {
                user = this.accountInstance.getMessagesController().getUser(Integer.valueOf(messageObject.messageOwner.from_id));
            }
            if ((this.botCount != 1 || username) && user != null && user.bot && !command.contains("@")) {
                text = String.format(Locale.US, "%s@%s", command, user.username) + " " + text2.replaceFirst("^/[a-zA-Z@\\d_]{1,255}(\\s|$)", "");
            } else {
                text = command + " " + text2.replaceFirst("^/[a-zA-Z@\\d_]{1,255}(\\s|$)", "");
            }
            this.ignoreTextChange = true;
            this.messageEditText.setText(text);
            EditTextCaption editTextCaption = this.messageEditText;
            editTextCaption.setSelection(editTextCaption.getText().length());
            this.ignoreTextChange = false;
            ChatActivityEnterViewDelegate chatActivityEnterViewDelegate = this.delegate;
            if (chatActivityEnterViewDelegate != null) {
                chatActivityEnterViewDelegate.onTextChanged(this.messageEditText.getText(), true);
            }
            if (!this.keyboardVisible && this.currentPopupContentType == -1) {
                openKeyboard();
                return;
            }
            return;
        }
        if (this.slowModeTimer > 0 && !isInScheduleMode()) {
            ChatActivityEnterViewDelegate chatActivityEnterViewDelegate2 = this.delegate;
            if (chatActivityEnterViewDelegate2 != null) {
                SimpleTextView simpleTextView = this.slowModeButton;
                chatActivityEnterViewDelegate2.onUpdateSlowModeButton(simpleTextView, true, simpleTextView.getText());
                return;
            }
            return;
        }
        if (messageObject != null && ((int) this.dialog_id) < 0) {
            user = this.accountInstance.getMessagesController().getUser(Integer.valueOf(messageObject.messageOwner.from_id));
        }
        TLRPC.User user2 = user;
        if ((this.botCount != 1 || username) && user2 != null && user2.bot && !command.contains("@")) {
            SendMessagesHelper.getInstance(this.currentAccount).sendMessage(String.format(Locale.US, "%s@%s", command, user2.username), this.dialog_id, this.replyingMessageObject, null, false, null, null, null, true, 0);
        } else {
            SendMessagesHelper.getInstance(this.currentAccount).sendMessage(command, this.dialog_id, this.replyingMessageObject, null, false, null, null, null, true, 0);
        }
    }

    public void setEditingMessageObject(MessageObject messageObject, boolean caption) {
        CharSequence editingText;
        if (this.audioToSend != null || this.videoToSendMessageObject != null || this.editingMessageObject == messageObject) {
            return;
        }
        int i = 1;
        if (this.editingMessageReqId != 0) {
            ConnectionsManager.getInstance(this.currentAccount).cancelRequest(this.editingMessageReqId, true);
            this.editingMessageReqId = 0;
        }
        this.editingMessageObject = messageObject;
        this.editingCaption = caption;
        if (messageObject != null) {
            AnimatorSet animatorSet = this.doneButtonAnimation;
            if (animatorSet != null) {
                animatorSet.cancel();
                this.doneButtonAnimation = null;
            }
            this.doneButtonContainer.setVisibility(0);
            showEditDoneProgress(true, false);
            InputFilter[] inputFilters = new InputFilter[1];
            if (caption) {
                inputFilters[0] = new InputFilter.LengthFilter(this.accountInstance.getMessagesController().maxCaptionLength);
                editingText = this.editingMessageObject.caption;
            } else {
                inputFilters[0] = new InputFilter.LengthFilter(this.accountInstance.getMessagesController().maxMessageLength);
                editingText = this.editingMessageObject.messageText;
            }
            if (editingText != null) {
                ArrayList<TLRPC.MessageEntity> entities = this.editingMessageObject.messageOwner.entities;
                MediaDataController.sortEntities(entities);
                SpannableStringBuilder stringBuilder = new SpannableStringBuilder(editingText);
                Object[] spansToRemove = stringBuilder.getSpans(0, stringBuilder.length(), Object.class);
                if (spansToRemove != null && spansToRemove.length > 0) {
                    for (Object obj : spansToRemove) {
                        stringBuilder.removeSpan(obj);
                    }
                }
                if (entities != null) {
                    int a = 0;
                    while (a < entities.size()) {
                        try {
                            TLRPC.MessageEntity entity = entities.get(a);
                            if (entity.offset + entity.length <= stringBuilder.length()) {
                                if (entity instanceof TLRPC.TL_inputMessageEntityMentionName) {
                                    if (entity.offset + entity.length < stringBuilder.length() && stringBuilder.charAt(entity.offset + entity.length) == ' ') {
                                        entity.length += i;
                                    }
                                    stringBuilder.setSpan(new URLSpanUserMention("" + ((TLRPC.TL_inputMessageEntityMentionName) entity).user_id.user_id, i), entity.offset, entity.offset + entity.length, 33);
                                } else if (entity instanceof TLRPC.TL_messageEntityMentionName) {
                                    if (entity.offset + entity.length < stringBuilder.length() && stringBuilder.charAt(entity.offset + entity.length) == ' ') {
                                        entity.length++;
                                    }
                                    stringBuilder.setSpan(new URLSpanUserMention("" + ((TLRPC.TL_messageEntityMentionName) entity).user_id, 1), entity.offset, entity.offset + entity.length, 33);
                                } else if ((entity instanceof TLRPC.TL_messageEntityCode) || (entity instanceof TLRPC.TL_messageEntityPre)) {
                                    TextStyleSpan.TextStyleRun run = new TextStyleSpan.TextStyleRun();
                                    run.flags |= 4;
                                    MediaDataController.addStyleToText(new TextStyleSpan(run), entity.offset, entity.offset + entity.length, stringBuilder, true);
                                } else if (entity instanceof TLRPC.TL_messageEntityBold) {
                                    TextStyleSpan.TextStyleRun run2 = new TextStyleSpan.TextStyleRun();
                                    run2.flags |= 1;
                                    MediaDataController.addStyleToText(new TextStyleSpan(run2), entity.offset, entity.offset + entity.length, stringBuilder, true);
                                } else if (entity instanceof TLRPC.TL_messageEntityItalic) {
                                    TextStyleSpan.TextStyleRun run3 = new TextStyleSpan.TextStyleRun();
                                    run3.flags |= 2;
                                    MediaDataController.addStyleToText(new TextStyleSpan(run3), entity.offset, entity.offset + entity.length, stringBuilder, true);
                                } else if (entity instanceof TLRPC.TL_messageEntityStrike) {
                                    TextStyleSpan.TextStyleRun run4 = new TextStyleSpan.TextStyleRun();
                                    run4.flags |= 8;
                                    MediaDataController.addStyleToText(new TextStyleSpan(run4), entity.offset, entity.offset + entity.length, stringBuilder, true);
                                } else if (entity instanceof TLRPC.TL_messageEntityUnderline) {
                                    TextStyleSpan.TextStyleRun run5 = new TextStyleSpan.TextStyleRun();
                                    run5.flags |= 16;
                                    MediaDataController.addStyleToText(new TextStyleSpan(run5), entity.offset, entity.offset + entity.length, stringBuilder, true);
                                } else if (entity instanceof TLRPC.TL_messageEntityTextUrl) {
                                    stringBuilder.setSpan(new URLSpanReplacement(entity.url), entity.offset, entity.offset + entity.length, 33);
                                }
                            }
                            a++;
                            i = 1;
                        } catch (Exception e) {
                            FileLog.e(e);
                        }
                    }
                }
                setFieldText(Emoji.replaceEmoji(new SpannableStringBuilder(stringBuilder), this.messageEditText.getPaint().getFontMetricsInt(), AndroidUtilities.dp(20.0f), false));
            } else {
                setFieldText("");
            }
            this.messageEditText.setFilters(inputFilters);
            openKeyboard();
            FrameLayout.LayoutParams layoutParams = (FrameLayout.LayoutParams) this.messageEditText.getLayoutParams();
            layoutParams.rightMargin = AndroidUtilities.dp(4.0f);
            this.messageEditText.setLayoutParams(layoutParams);
            this.sendButton.setVisibility(8);
            this.slowModeButton.setVisibility(8);
            this.cancelBotButton.setVisibility(8);
            this.audioVideoButtonContainer.setVisibility(8);
            this.attachLayout.setVisibility(8);
            this.sendButtonContainer.setVisibility(8);
            ImageView imageView = this.scheduledButton;
            if (imageView != null) {
                imageView.setVisibility(8);
            }
        } else {
            this.doneButtonContainer.setVisibility(8);
            this.messageEditText.setFilters(new InputFilter[0]);
            this.delegate.onMessageEditEnd(false);
            this.sendButtonContainer.setVisibility(0);
            this.cancelBotButton.setScaleX(0.1f);
            this.cancelBotButton.setScaleY(0.1f);
            this.cancelBotButton.setAlpha(0.0f);
            this.cancelBotButton.setVisibility(8);
            if (this.slowModeTimer > 0 && !isInScheduleMode()) {
                if (this.slowModeTimer == Integer.MAX_VALUE) {
                    this.sendButton.setScaleX(1.0f);
                    this.sendButton.setScaleY(1.0f);
                    this.sendButton.setAlpha(1.0f);
                    this.sendButton.setVisibility(0);
                    this.slowModeButton.setScaleX(0.1f);
                    this.slowModeButton.setScaleY(0.1f);
                    this.slowModeButton.setAlpha(0.0f);
                    this.slowModeButton.setVisibility(8);
                } else {
                    this.sendButton.setScaleX(0.1f);
                    this.sendButton.setScaleY(0.1f);
                    this.sendButton.setAlpha(0.0f);
                    this.sendButton.setVisibility(8);
                    this.slowModeButton.setScaleX(1.0f);
                    this.slowModeButton.setScaleY(1.0f);
                    this.slowModeButton.setAlpha(1.0f);
                    this.slowModeButton.setVisibility(0);
                }
                this.attachLayout.setScaleX(0.01f);
                this.attachLayout.setAlpha(0.0f);
                this.attachLayout.setVisibility(8);
                this.audioVideoButtonContainer.setScaleX(0.1f);
                this.audioVideoButtonContainer.setScaleY(0.1f);
                this.audioVideoButtonContainer.setAlpha(0.0f);
                this.audioVideoButtonContainer.setVisibility(8);
            } else {
                this.sendButton.setScaleX(0.1f);
                this.sendButton.setScaleY(0.1f);
                this.sendButton.setAlpha(0.0f);
                this.sendButton.setVisibility(8);
                this.slowModeButton.setScaleX(0.1f);
                this.slowModeButton.setScaleY(0.1f);
                this.slowModeButton.setAlpha(0.0f);
                this.slowModeButton.setVisibility(8);
                this.attachLayout.setScaleX(1.0f);
                this.attachLayout.setAlpha(1.0f);
                this.attachLayout.setVisibility(0);
                this.audioVideoButtonContainer.setScaleX(1.0f);
                this.audioVideoButtonContainer.setScaleY(1.0f);
                this.audioVideoButtonContainer.setAlpha(1.0f);
                this.audioVideoButtonContainer.setVisibility(0);
            }
            if (this.scheduledButton.getTag() != null) {
                this.scheduledButton.setScaleX(1.0f);
                this.scheduledButton.setScaleY(1.0f);
                this.scheduledButton.setAlpha(1.0f);
                this.scheduledButton.setVisibility(0);
            }
            this.messageEditText.setText("");
            if (getVisibility() == 0) {
                this.delegate.onAttachButtonShow();
            }
            updateFieldRight(1);
        }
        updateFieldHint();
    }

    public ImageView getAttachButton() {
        return this.attachButton;
    }

    public View getSendButton() {
        return this.sendButton.getVisibility() == 0 ? this.sendButton : this.audioVideoButtonContainer;
    }

    public EmojiView getEmojiView() {
        return this.emojiView;
    }

    public void setFieldText(CharSequence text) {
        setFieldText(text, true);
    }

    public void setFieldText(CharSequence text, boolean ignoreChange) {
        ChatActivityEnterViewDelegate chatActivityEnterViewDelegate;
        EditTextCaption editTextCaption = this.messageEditText;
        if (editTextCaption == null) {
            return;
        }
        this.ignoreTextChange = ignoreChange;
        editTextCaption.setText(text);
        EditTextCaption editTextCaption2 = this.messageEditText;
        editTextCaption2.setSelection(editTextCaption2.getText().length());
        this.ignoreTextChange = false;
        if (ignoreChange && (chatActivityEnterViewDelegate = this.delegate) != null) {
            chatActivityEnterViewDelegate.onTextChanged(this.messageEditText.getText(), true);
        }
    }

    public void setSelection(int start) {
        EditTextCaption editTextCaption = this.messageEditText;
        if (editTextCaption == null) {
            return;
        }
        editTextCaption.setSelection(start, editTextCaption.length());
    }

    public int getCursorPosition() {
        EditTextCaption editTextCaption = this.messageEditText;
        if (editTextCaption == null) {
            return 0;
        }
        return editTextCaption.getSelectionStart();
    }

    public int getSelectionLength() {
        EditTextCaption editTextCaption = this.messageEditText;
        if (editTextCaption == null) {
            return 0;
        }
        try {
            return editTextCaption.getSelectionEnd() - this.messageEditText.getSelectionStart();
        } catch (Exception e) {
            FileLog.e(e);
            return 0;
        }
    }

    public void replaceWithText(int start, int len, CharSequence text, boolean parseEmoji) {
        try {
            SpannableStringBuilder builder = new SpannableStringBuilder(this.messageEditText.getText());
            builder.replace(start, start + len, text);
            if (parseEmoji) {
                Emoji.replaceEmoji(builder, this.messageEditText.getPaint().getFontMetricsInt(), AndroidUtilities.dp(20.0f), false);
            }
            this.messageEditText.setText(builder);
            this.messageEditText.setSelection(text.length() + start);
        } catch (Exception e) {
            FileLog.e(e);
        }
    }

    public void addMentionText1(int start, int len, CharSequence text, boolean parseEmoji) {
        try {
            SpannableStringBuilder builder = new SpannableStringBuilder(this.messageEditText.getText());
            builder.replace(start, start + len, text);
            if (parseEmoji) {
                Emoji.replaceEmoji(builder, this.messageEditText.getPaint().getFontMetricsInt(), AndroidUtilities.dp(20.0f), false);
            }
            this.messageEditText.setText(builder);
            this.messageEditText.setSelection(text.length() + start);
        } catch (Exception e) {
            FileLog.e(e);
        }
    }

    public void mentionAll(int start, int len, CharSequence text, boolean parseEmoji) {
        try {
            SpannableStringBuilder builder = new SpannableStringBuilder(this.messageEditText.getText());
            builder.replace(start, start + len, text);
            if (parseEmoji) {
                Emoji.replaceEmoji(builder, this.messageEditText.getPaint().getFontMetricsInt(), AndroidUtilities.dp(20.0f), false);
            }
            this.messageEditText.setText(builder);
            this.messageEditText.setSelection(text.length() + start);
        } catch (Exception e) {
            FileLog.e(e);
        }
    }

    public void addMentionText(int start, int len, CharSequence text, boolean parseEmoji) {
        try {
            SpannableStringBuilder builder = new SpannableStringBuilder(this.messageEditText.getText());
            Editable editable = this.messageEditText.getText();
            if (editable != null) {
                String content = editable.toString();
                if (!content.isEmpty() && !content.endsWith(" ")) {
                    builder.append((CharSequence) " ");
                    start++;
                }
            }
            builder.append((CharSequence) "@");
            builder.replace(start, start + len, text);
            if (parseEmoji) {
                Emoji.replaceEmoji(builder, this.messageEditText.getPaint().getFontMetricsInt(), AndroidUtilities.dp(20.0f), false);
            }
            this.messageEditText.setText(builder);
            this.messageEditText.setSelection(text.length() + start);
        } catch (Exception e) {
            FileLog.e(e);
        }
    }

    public void setFieldFocused() {
        AccessibilityManager am = (AccessibilityManager) this.parentActivity.getSystemService("accessibility");
        if (this.messageEditText != null && !am.isTouchExplorationEnabled()) {
            try {
                this.messageEditText.requestFocus();
            } catch (Exception e) {
                FileLog.e(e);
            }
        }
    }

    public void setFieldFocused(boolean focus) {
        AccessibilityManager am = (AccessibilityManager) this.parentActivity.getSystemService("accessibility");
        if (this.messageEditText == null || am.isTouchExplorationEnabled()) {
            return;
        }
        if (focus) {
            if (this.searchingType == 0 && !this.messageEditText.isFocused()) {
                Runnable runnable = new Runnable() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$ChatActivityEnterView$mLJSDj0uq1X7uzgVJiYOQPgT500
                    @Override // java.lang.Runnable
                    public final void run() {
                        this.f$0.lambda$setFieldFocused$23$ChatActivityEnterView();
                    }
                };
                this.focusRunnable = runnable;
                AndroidUtilities.runOnUIThread(runnable, 600L);
                return;
            }
            return;
        }
        EditTextCaption editTextCaption = this.messageEditText;
        if (editTextCaption != null && editTextCaption.isFocused() && !this.keyboardVisible) {
            this.messageEditText.clearFocus();
        }
    }

    public /* synthetic */ void lambda$setFieldFocused$23$ChatActivityEnterView() {
        boolean allowFocus;
        EditTextCaption editTextCaption;
        LaunchActivity launchActivity;
        this.focusRunnable = null;
        if (AndroidUtilities.isTablet()) {
            Activity activity = this.parentActivity;
            if ((activity instanceof LaunchActivity) && (launchActivity = (LaunchActivity) activity) != null) {
                View layout = launchActivity.getLayersActionBarLayout();
                allowFocus = layout == null || layout.getVisibility() != 0;
            } else {
                allowFocus = true;
            }
        } else {
            allowFocus = true;
        }
        if (!this.isPaused && allowFocus && (editTextCaption = this.messageEditText) != null) {
            try {
                editTextCaption.requestFocus();
            } catch (Exception e) {
                FileLog.e(e);
            }
        }
    }

    public boolean hasText() {
        EditTextCaption editTextCaption = this.messageEditText;
        return editTextCaption != null && editTextCaption.length() > 0;
    }

    public EditTextCaption getEditField() {
        return this.messageEditText;
    }

    public CharSequence getFieldText() {
        if (hasText()) {
            return this.messageEditText.getText();
        }
        return null;
    }

    public void updateScheduleButton(boolean animated) {
        ImageView imageView;
        ImageView imageView2;
        boolean notifyVisible = false;
        if (((int) this.dialog_id) < 0) {
            TLRPC.Chat currentChat = this.accountInstance.getMessagesController().getChat(Integer.valueOf(-((int) this.dialog_id)));
            this.silent = MessagesController.getNotificationsSettings(this.currentAccount).getBoolean("silent_" + this.dialog_id, false);
            this.canWriteToChannel = ChatObject.isChannel(currentChat) && (currentChat.creator || (currentChat.admin_rights != null && currentChat.admin_rights.post_messages)) && !currentChat.megagroup;
            ImageView imageView3 = this.notifyButton;
            if (imageView3 != null) {
                notifyVisible = this.canWriteToChannel;
                imageView3.setImageResource(this.silent ? R.drawable.input_notify_off : R.drawable.input_notify_on);
            }
            LinearLayout linearLayout = this.attachLayout;
            if (linearLayout != null) {
                updateFieldRight(linearLayout.getVisibility() == 0 ? 1 : 0);
            }
        }
        boolean hasScheduled = (this.delegate == null || isInScheduleMode() || !this.delegate.hasScheduledMessages()) ? false : true;
        final boolean visible = hasScheduled && !this.scheduleButtonHidden;
        ImageView imageView4 = this.scheduledButton;
        float f = 96.0f;
        if (imageView4 != null) {
            if ((imageView4.getTag() != null && visible) || (this.scheduledButton.getTag() == null && !visible)) {
                if (this.notifyButton != null) {
                    int newVisibility = (hasScheduled || !notifyVisible || this.scheduledButton.getVisibility() == 0) ? 8 : 0;
                    if (newVisibility != this.notifyButton.getVisibility()) {
                        this.notifyButton.setVisibility(newVisibility);
                        LinearLayout linearLayout2 = this.attachLayout;
                        if (linearLayout2 != null) {
                            ImageView imageView5 = this.botButton;
                            if ((imageView5 == null || imageView5.getVisibility() == 8) && ((imageView2 = this.notifyButton) == null || imageView2.getVisibility() == 8)) {
                                f = 48.0f;
                            }
                            linearLayout2.setPivotX(AndroidUtilities.dp(f));
                            return;
                        }
                        return;
                    }
                    return;
                }
                return;
            }
            this.scheduledButton.setTag(visible ? 1 : null);
        }
        AnimatorSet animatorSet = this.scheduledButtonAnimation;
        if (animatorSet != null) {
            animatorSet.cancel();
            this.scheduledButtonAnimation = null;
        }
        if (!animated || notifyVisible) {
            ImageView imageView6 = this.scheduledButton;
            if (imageView6 != null) {
                imageView6.setVisibility(visible ? 0 : 8);
                this.scheduledButton.setAlpha(visible ? 1.0f : 0.0f);
                this.scheduledButton.setScaleX(visible ? 1.0f : 0.1f);
                this.scheduledButton.setScaleY(visible ? 1.0f : 0.1f);
            }
            ImageView imageView7 = this.notifyButton;
            if (imageView7 != null) {
                imageView7.setVisibility((!notifyVisible || this.scheduledButton.getVisibility() == 0) ? 8 : 0);
            }
        } else {
            if (visible) {
                this.scheduledButton.setVisibility(0);
            }
            this.scheduledButton.setPivotX(AndroidUtilities.dp(24.0f));
            AnimatorSet animatorSet2 = new AnimatorSet();
            this.scheduledButtonAnimation = animatorSet2;
            Animator[] animatorArr = new Animator[3];
            ImageView imageView8 = this.scheduledButton;
            Property property = View.ALPHA;
            float[] fArr = new float[1];
            fArr[0] = visible ? 1.0f : 0.0f;
            animatorArr[0] = ObjectAnimator.ofFloat(imageView8, (Property<ImageView, Float>) property, fArr);
            ImageView imageView9 = this.scheduledButton;
            Property property2 = View.SCALE_X;
            float[] fArr2 = new float[1];
            fArr2[0] = visible ? 1.0f : 0.1f;
            animatorArr[1] = ObjectAnimator.ofFloat(imageView9, (Property<ImageView, Float>) property2, fArr2);
            ImageView imageView10 = this.scheduledButton;
            Property property3 = View.SCALE_Y;
            float[] fArr3 = new float[1];
            fArr3[0] = visible ? 1.0f : 0.1f;
            animatorArr[2] = ObjectAnimator.ofFloat(imageView10, (Property<ImageView, Float>) property3, fArr3);
            animatorSet2.playTogether(animatorArr);
            this.scheduledButtonAnimation.setDuration(180L);
            this.scheduledButtonAnimation.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.components.ChatActivityEnterView.34
                @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                public void onAnimationEnd(Animator animation) {
                    ChatActivityEnterView.this.scheduledButtonAnimation = null;
                    if (!visible) {
                        ChatActivityEnterView.this.scheduledButton.setVisibility(8);
                    }
                }
            });
            this.scheduledButtonAnimation.start();
        }
        LinearLayout linearLayout3 = this.attachLayout;
        if (linearLayout3 != null) {
            ImageView imageView11 = this.botButton;
            if ((imageView11 == null || imageView11.getVisibility() == 8) && ((imageView = this.notifyButton) == null || imageView.getVisibility() == 8)) {
                f = 48.0f;
            }
            linearLayout3.setPivotX(AndroidUtilities.dp(f));
        }
    }

    private void updateBotButton() {
        ImageView imageView;
        ImageView imageView2 = this.botButton;
        if (imageView2 == null) {
            return;
        }
        if (this.hasBotCommands || this.botReplyMarkup != null) {
            if (this.botButton.getVisibility() != 0) {
                this.botButton.setVisibility(0);
            }
            if (this.botReplyMarkup != null) {
                if (isPopupShowing() && this.currentPopupContentType == 1) {
                    this.botButton.setImageResource(R.drawable.input_keyboard);
                    this.botButton.setContentDescription(LocaleController.getString("AccDescrShowKeyboard", R.string.AccDescrShowKeyboard));
                } else {
                    this.botButton.setImageResource(R.drawable.input_bot2);
                    this.botButton.setContentDescription(LocaleController.getString("AccDescrBotKeyboard", R.string.AccDescrBotKeyboard));
                }
            } else {
                this.botButton.setImageResource(R.drawable.input_bot1);
                this.botButton.setContentDescription(LocaleController.getString("AccDescrBotCommands", R.string.AccDescrBotCommands));
            }
        } else {
            imageView2.setVisibility(8);
        }
        updateFieldRight(2);
        LinearLayout linearLayout = this.attachLayout;
        ImageView imageView3 = this.botButton;
        linearLayout.setPivotX(AndroidUtilities.dp(((imageView3 == null || imageView3.getVisibility() == 8) && ((imageView = this.notifyButton) == null || imageView.getVisibility() == 8)) ? 48.0f : 96.0f));
    }

    public boolean isRtlText() {
        try {
            return this.messageEditText.getLayout().getParagraphDirection(0) == -1;
        } catch (Throwable th) {
            return false;
        }
    }

    public void setBotsCount(int count, boolean hasCommands) {
        this.botCount = count;
        if (this.hasBotCommands != hasCommands) {
            this.hasBotCommands = hasCommands;
            updateBotButton();
        }
    }

    public void setButtons(MessageObject messageObject) {
        setButtons(messageObject, true);
    }

    public void setButtons(MessageObject messageObject, boolean openKeyboard) {
        MessageObject messageObject2 = this.replyingMessageObject;
        if (messageObject2 != null && messageObject2 == this.botButtonsMessageObject && messageObject2 != messageObject) {
            this.botMessageObject = messageObject;
            return;
        }
        if (this.botButton != null) {
            MessageObject messageObject3 = this.botButtonsMessageObject;
            if (messageObject3 == null || messageObject3 != messageObject) {
                if (this.botButtonsMessageObject == null && messageObject == null) {
                    return;
                }
                if (this.botKeyboardView == null) {
                    BotKeyboardView botKeyboardView = new BotKeyboardView(this.parentActivity);
                    this.botKeyboardView = botKeyboardView;
                    botKeyboardView.setVisibility(8);
                    this.botKeyboardView.setDelegate(new BotKeyboardView.BotKeyboardViewDelegate() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$ChatActivityEnterView$NyW5HLs3677d4vNMkfutyb-LsOg
                        @Override // im.uwrkaxlmjj.ui.components.BotKeyboardView.BotKeyboardViewDelegate
                        public final void didPressedButton(TLRPC.KeyboardButton keyboardButton) {
                            this.f$0.lambda$setButtons$24$ChatActivityEnterView(keyboardButton);
                        }
                    });
                    SizeNotifierFrameLayout sizeNotifierFrameLayout = this.sizeNotifierLayout;
                    sizeNotifierFrameLayout.addView(this.botKeyboardView, sizeNotifierFrameLayout.getChildCount() - 1);
                }
                this.botButtonsMessageObject = messageObject;
                this.botReplyMarkup = (messageObject == null || !(messageObject.messageOwner.reply_markup instanceof TLRPC.TL_replyKeyboardMarkup)) ? null : (TLRPC.TL_replyKeyboardMarkup) messageObject.messageOwner.reply_markup;
                this.botKeyboardView.setPanelHeight(AndroidUtilities.displaySize.x > AndroidUtilities.displaySize.y ? this.keyboardHeightLand : this.keyboardHeight);
                this.botKeyboardView.setButtons(this.botReplyMarkup);
                if (this.botReplyMarkup != null) {
                    SharedPreferences preferences = MessagesController.getMainSettings(this.currentAccount);
                    StringBuilder sb = new StringBuilder();
                    sb.append("hidekeyboard_");
                    sb.append(this.dialog_id);
                    boolean keyboardHidden = preferences.getInt(sb.toString(), 0) == messageObject.getId();
                    boolean showPopup = true;
                    if (this.botButtonsMessageObject != this.replyingMessageObject && this.botReplyMarkup.single_use) {
                        if (preferences.getInt("answered_" + this.dialog_id, 0) == messageObject.getId()) {
                            showPopup = false;
                        }
                    }
                    if (showPopup && !keyboardHidden && this.messageEditText.length() == 0 && !isPopupShowing()) {
                        showPopup(1, 1);
                    }
                } else if (isPopupShowing() && this.currentPopupContentType == 1) {
                    if (openKeyboard) {
                        openKeyboardInternal();
                    } else {
                        showPopup(0, 1);
                    }
                }
                updateBotButton();
            }
        }
    }

    public /* synthetic */ void lambda$setButtons$24$ChatActivityEnterView(TLRPC.KeyboardButton button) {
        MessageObject object = this.replyingMessageObject;
        if (object == null) {
            object = ((int) this.dialog_id) < 0 ? this.botButtonsMessageObject : null;
        }
        MessageObject messageObject = this.replyingMessageObject;
        if (messageObject == null) {
            messageObject = this.botButtonsMessageObject;
        }
        didPressedBotButton(button, object, messageObject);
        if (this.replyingMessageObject != null) {
            openKeyboardInternal();
            setButtons(this.botMessageObject, false);
        } else if (this.botButtonsMessageObject.messageOwner.reply_markup.single_use) {
            openKeyboardInternal();
            SharedPreferences preferences = MessagesController.getMainSettings(this.currentAccount);
            preferences.edit().putInt("answered_" + this.dialog_id, this.botButtonsMessageObject.getId()).commit();
        }
        ChatActivityEnterViewDelegate chatActivityEnterViewDelegate = this.delegate;
        if (chatActivityEnterViewDelegate != null) {
            chatActivityEnterViewDelegate.onMessageSend(null, true, 0);
        }
    }

    public void didPressedBotButton(final TLRPC.KeyboardButton button, MessageObject replyMessageObject, final MessageObject messageObject) {
        if (button == null || messageObject == null) {
            return;
        }
        if (button instanceof TLRPC.TL_keyboardButton) {
            SendMessagesHelper.getInstance(this.currentAccount).sendMessage(button.text, this.dialog_id, replyMessageObject, null, false, null, null, null, true, 0);
            return;
        }
        if (button instanceof TLRPC.TL_keyboardButtonUrl) {
            this.parentFragment.showOpenUrlAlert(button.url, true);
            return;
        }
        if (button instanceof TLRPC.TL_keyboardButtonRequestPhone) {
            this.parentFragment.shareMyContact(2, messageObject);
            return;
        }
        if (button instanceof TLRPC.TL_keyboardButtonRequestGeoLocation) {
            AlertDialog.Builder builder = new AlertDialog.Builder(this.parentActivity);
            builder.setTitle(LocaleController.getString("ShareYouLocationTitle", R.string.ShareYouLocationTitle));
            builder.setMessage(LocaleController.getString("ShareYouLocationInfo", R.string.ShareYouLocationInfo));
            builder.setPositiveButton(LocaleController.getString("OK", R.string.OK), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$ChatActivityEnterView$-fWZ0SbhfRq_RPbo01N6UlhYjTY
                @Override // android.content.DialogInterface.OnClickListener
                public final void onClick(DialogInterface dialogInterface, int i) {
                    this.f$0.lambda$didPressedBotButton$25$ChatActivityEnterView(messageObject, button, dialogInterface, i);
                }
            });
            builder.setNegativeButton(LocaleController.getString("Cancel", R.string.Cancel), null);
            this.parentFragment.showDialog(builder.create());
            return;
        }
        if ((button instanceof TLRPC.TL_keyboardButtonCallback) || (button instanceof TLRPC.TL_keyboardButtonGame) || (button instanceof TLRPC.TL_keyboardButtonBuy) || (button instanceof TLRPC.TL_keyboardButtonUrlAuth)) {
            SendMessagesHelper.getInstance(this.currentAccount).sendCallback(true, messageObject, button, this.parentFragment);
            return;
        }
        if (!(button instanceof TLRPC.TL_keyboardButtonSwitchInline) || this.parentFragment.processSwitchButton((TLRPC.TL_keyboardButtonSwitchInline) button)) {
            return;
        }
        if (button.same_peer) {
            int uid = messageObject.messageOwner.from_id;
            if (messageObject.messageOwner.via_bot_id != 0) {
                uid = messageObject.messageOwner.via_bot_id;
            }
            TLRPC.User user = this.accountInstance.getMessagesController().getUser(Integer.valueOf(uid));
            if (user == null) {
                return;
            }
            setFieldText("@" + user.username + " " + button.query);
            return;
        }
        Bundle args = new Bundle();
        args.putBoolean("onlySelect", true);
        args.putInt("dialogsType", 1);
        DialogsActivity fragment = new DialogsActivity(args);
        fragment.setDelegate(new DialogsActivity.DialogsActivityDelegate() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$ChatActivityEnterView$O6TgCR7VGb5SWYHZskxtkf6ucH8
            @Override // im.uwrkaxlmjj.ui.DialogsActivity.DialogsActivityDelegate
            public final void didSelectDialogs(DialogsActivity dialogsActivity, ArrayList arrayList, CharSequence charSequence, boolean z) {
                this.f$0.lambda$didPressedBotButton$26$ChatActivityEnterView(messageObject, button, dialogsActivity, arrayList, charSequence, z);
            }
        });
        this.parentFragment.presentFragment(fragment);
    }

    public /* synthetic */ void lambda$didPressedBotButton$25$ChatActivityEnterView(MessageObject messageObject, TLRPC.KeyboardButton button, DialogInterface dialogInterface, int i) {
        if (Build.VERSION.SDK_INT >= 23 && this.parentActivity.checkSelfPermission(PermissionUtils.PERMISSION_ACCESS_COARSE_LOCATION) != 0) {
            this.parentActivity.requestPermissions(new String[]{PermissionUtils.PERMISSION_ACCESS_COARSE_LOCATION, "android.permission.ACCESS_FINE_LOCATION"}, 2);
            this.pendingMessageObject = messageObject;
            this.pendingLocationButton = button;
            return;
        }
        SendMessagesHelper.getInstance(this.currentAccount).sendCurrentLocation(messageObject, button);
    }

    public /* synthetic */ void lambda$didPressedBotButton$26$ChatActivityEnterView(MessageObject messageObject, TLRPC.KeyboardButton button, DialogsActivity fragment1, ArrayList dids, CharSequence message, boolean param) {
        int uid = messageObject.messageOwner.from_id;
        if (messageObject.messageOwner.via_bot_id != 0) {
            uid = messageObject.messageOwner.via_bot_id;
        }
        TLRPC.User user = this.accountInstance.getMessagesController().getUser(Integer.valueOf(uid));
        if (user == null) {
            fragment1.finishFragment();
            return;
        }
        long did = ((Long) dids.get(0)).longValue();
        MediaDataController.getInstance(this.currentAccount).saveDraft(did, "@" + user.username + " " + button.query, null, null, true);
        if (did != this.dialog_id) {
            int lower_part = (int) did;
            if (lower_part != 0) {
                Bundle args1 = new Bundle();
                if (lower_part > 0) {
                    args1.putInt("user_id", lower_part);
                } else if (lower_part < 0) {
                    args1.putInt("chat_id", -lower_part);
                }
                if (!this.accountInstance.getMessagesController().checkCanOpenChat(args1, fragment1)) {
                    return;
                }
                ChatActivity chatActivity = new ChatActivity(args1);
                if (this.parentFragment.presentFragment(chatActivity, true)) {
                    if (!AndroidUtilities.isTablet()) {
                        this.parentFragment.removeSelfFromStack();
                        return;
                    }
                    return;
                }
                fragment1.finishFragment();
                return;
            }
            fragment1.finishFragment();
            return;
        }
        fragment1.finishFragment();
    }

    public boolean isPopupView(View view) {
        return view == this.botKeyboardView || view == this.emojiView || view == this.menuView;
    }

    public boolean isRecordCircle(View view) {
        return view == this.recordCircle;
    }

    private void createEmojiView() {
        if (this.emojiView != null) {
            return;
        }
        EmojiView emojiView = new EmojiView(this.allowStickers, this.allowGifs, this.parentActivity, true, this.info);
        this.emojiView = emojiView;
        emojiView.setVisibility(8);
        this.emojiView.setDelegate(new AnonymousClass35());
        this.emojiView.setDragListener(new EmojiView.DragListener() { // from class: im.uwrkaxlmjj.ui.components.ChatActivityEnterView.36
            int initialOffset;
            boolean wasExpanded;

            @Override // im.uwrkaxlmjj.ui.components.EmojiView.DragListener
            public void onDragStart() {
                if (allowDragging()) {
                    if (ChatActivityEnterView.this.stickersExpansionAnim != null) {
                        ChatActivityEnterView.this.stickersExpansionAnim.cancel();
                    }
                    ChatActivityEnterView.this.stickersDragging = true;
                    this.wasExpanded = ChatActivityEnterView.this.stickersExpanded;
                    ChatActivityEnterView.this.stickersExpanded = true;
                    NotificationCenter.getGlobalInstance().postNotificationName(NotificationCenter.stopAllHeavyOperations, 1);
                    ChatActivityEnterView chatActivityEnterView = ChatActivityEnterView.this;
                    chatActivityEnterView.stickersExpandedHeight = (((chatActivityEnterView.sizeNotifierLayout.getHeight() - (Build.VERSION.SDK_INT >= 21 ? AndroidUtilities.statusBarHeight : 0)) - ActionBar.getCurrentActionBarHeight()) - ChatActivityEnterView.this.getHeight()) + Theme.chat_composeShadowDrawable.getIntrinsicHeight();
                    if (ChatActivityEnterView.this.searchingType == 2) {
                        ChatActivityEnterView chatActivityEnterView2 = ChatActivityEnterView.this;
                        chatActivityEnterView2.stickersExpandedHeight = Math.min(chatActivityEnterView2.stickersExpandedHeight, AndroidUtilities.dp(120.0f) + (AndroidUtilities.displaySize.x > AndroidUtilities.displaySize.y ? ChatActivityEnterView.this.keyboardHeightLand : ChatActivityEnterView.this.keyboardHeight));
                    }
                    ChatActivityEnterView.this.emojiView.getLayoutParams().height = ChatActivityEnterView.this.stickersExpandedHeight;
                    ChatActivityEnterView.this.emojiView.setLayerType(2, null);
                    ChatActivityEnterView.this.sizeNotifierLayout.requestLayout();
                    ChatActivityEnterView.this.sizeNotifierLayout.setForeground(ChatActivityEnterView.this.new ScrimDrawable());
                    this.initialOffset = (int) ChatActivityEnterView.this.getTranslationY();
                    if (ChatActivityEnterView.this.delegate != null) {
                        ChatActivityEnterView.this.delegate.onStickersExpandedChange();
                    }
                }
            }

            @Override // im.uwrkaxlmjj.ui.components.EmojiView.DragListener
            public void onDragEnd(float velocity) {
                if (allowDragging()) {
                    ChatActivityEnterView.this.stickersDragging = false;
                    if ((!this.wasExpanded || velocity < AndroidUtilities.dp(200.0f)) && ((this.wasExpanded || velocity > AndroidUtilities.dp(-200.0f)) && ((!this.wasExpanded || ChatActivityEnterView.this.stickersExpansionProgress > 0.6f) && (this.wasExpanded || ChatActivityEnterView.this.stickersExpansionProgress < 0.4f)))) {
                        ChatActivityEnterView.this.setStickersExpanded(this.wasExpanded, true, true);
                    } else {
                        ChatActivityEnterView.this.setStickersExpanded(!this.wasExpanded, true, true);
                    }
                }
            }

            @Override // im.uwrkaxlmjj.ui.components.EmojiView.DragListener
            public void onDragCancel() {
                if (ChatActivityEnterView.this.stickersTabOpen) {
                    ChatActivityEnterView.this.stickersDragging = false;
                    ChatActivityEnterView.this.setStickersExpanded(this.wasExpanded, true, false);
                }
            }

            @Override // im.uwrkaxlmjj.ui.components.EmojiView.DragListener
            public void onDrag(int offset) {
                if (!allowDragging()) {
                    return;
                }
                int origHeight = AndroidUtilities.displaySize.x > AndroidUtilities.displaySize.y ? ChatActivityEnterView.this.keyboardHeightLand : ChatActivityEnterView.this.keyboardHeight;
                int offset2 = Math.max(Math.min(offset + this.initialOffset, 0), -(ChatActivityEnterView.this.stickersExpandedHeight - origHeight));
                ChatActivityEnterView.this.emojiView.setTranslationY(offset2);
                ChatActivityEnterView.this.setTranslationY(offset2);
                ChatActivityEnterView.this.stickersExpansionProgress = offset2 / (-(r1.stickersExpandedHeight - origHeight));
                ChatActivityEnterView.this.sizeNotifierLayout.invalidate();
            }

            private boolean allowDragging() {
                return ChatActivityEnterView.this.stickersTabOpen && (ChatActivityEnterView.this.stickersExpanded || ChatActivityEnterView.this.messageEditText.length() <= 0) && ChatActivityEnterView.this.emojiView.areThereAnyStickers();
            }
        });
        this.sizeNotifierLayout.addView(this.emojiView, r0.getChildCount() - 1);
        checkChannelRights();
    }

    /* JADX INFO: renamed from: im.uwrkaxlmjj.ui.components.ChatActivityEnterView$35, reason: invalid class name */
    class AnonymousClass35 implements EmojiView.EmojiViewDelegate {
        AnonymousClass35() {
        }

        @Override // im.uwrkaxlmjj.ui.components.EmojiView.EmojiViewDelegate
        public boolean onBackspace() {
            if (ChatActivityEnterView.this.messageEditText.length() == 0) {
                return false;
            }
            ChatActivityEnterView.this.messageEditText.dispatchKeyEvent(new KeyEvent(0, 67));
            return true;
        }

        @Override // im.uwrkaxlmjj.ui.components.EmojiView.EmojiViewDelegate
        public void onEmojiSelected(String symbol) {
            int i = ChatActivityEnterView.this.messageEditText.getSelectionEnd();
            if (i < 0) {
                i = 0;
            }
            try {
                try {
                    ChatActivityEnterView.this.innerTextChange = 2;
                    CharSequence localCharSequence = Emoji.replaceEmoji(symbol, ChatActivityEnterView.this.messageEditText.getPaint().getFontMetricsInt(), AndroidUtilities.dp(20.0f), false);
                    ChatActivityEnterView.this.messageEditText.setText(ChatActivityEnterView.this.messageEditText.getText().insert(i, localCharSequence));
                    int j = localCharSequence.length() + i;
                    ChatActivityEnterView.this.messageEditText.setSelection(j, j);
                } catch (Exception e) {
                    FileLog.e(e);
                }
            } finally {
                ChatActivityEnterView.this.innerTextChange = 0;
            }
        }

        @Override // im.uwrkaxlmjj.ui.components.EmojiView.EmojiViewDelegate
        public void onStickerSelected(View view, TLRPC.Document sticker, Object parent, boolean notify, int scheduleDate) {
            if (ChatActivityEnterView.this.slowModeTimer <= 0 || isInScheduleMode()) {
                if (ChatActivityEnterView.this.stickersExpanded) {
                    if (ChatActivityEnterView.this.searchingType != 0) {
                        ChatActivityEnterView.this.searchingType = 0;
                        ChatActivityEnterView.this.emojiView.closeSearch(true, MessageObject.getStickerSetId(sticker));
                        ChatActivityEnterView.this.emojiView.hideSearchKeyboard();
                    }
                    ChatActivityEnterView.this.setStickersExpanded(false, true, false);
                }
                ChatActivityEnterView.this.lambda$onStickerSelected$28$ChatActivityEnterView(sticker, parent, false, notify, scheduleDate);
                if (((int) ChatActivityEnterView.this.dialog_id) == 0 && MessageObject.isGifDocument(sticker)) {
                    ChatActivityEnterView.this.accountInstance.getMessagesController().saveGif(parent, sticker);
                    return;
                }
                return;
            }
            if (ChatActivityEnterView.this.delegate != null) {
                ChatActivityEnterView.this.delegate.onUpdateSlowModeButton(view != null ? view : ChatActivityEnterView.this.slowModeButton, true, ChatActivityEnterView.this.slowModeButton.getText());
            }
        }

        @Override // im.uwrkaxlmjj.ui.components.EmojiView.EmojiViewDelegate
        public void onStickersSettingsClick() {
            if (ChatActivityEnterView.this.parentFragment != null) {
                ChatActivityEnterView.this.parentFragment.presentFragment(new StickersActivity(0));
            }
        }

        @Override // im.uwrkaxlmjj.ui.components.EmojiView.EmojiViewDelegate
        /* JADX INFO: renamed from: onGifSelected, reason: merged with bridge method [inline-methods] */
        public void lambda$onGifSelected$0$ChatActivityEnterView$35(final View view, final Object gif, final Object parent, boolean notify, int scheduleDate) {
            if (!isInScheduleMode() || scheduleDate != 0) {
                if (ChatActivityEnterView.this.slowModeTimer <= 0 || isInScheduleMode()) {
                    if (ChatActivityEnterView.this.stickersExpanded) {
                        if (ChatActivityEnterView.this.searchingType != 0) {
                            ChatActivityEnterView.this.emojiView.hideSearchKeyboard();
                        }
                        ChatActivityEnterView.this.setStickersExpanded(false, true, false);
                    }
                    if (gif instanceof TLRPC.Document) {
                        TLRPC.Document document = (TLRPC.Document) gif;
                        SendMessagesHelper.getInstance(ChatActivityEnterView.this.currentAccount).sendSticker(document, ChatActivityEnterView.this.dialog_id, ChatActivityEnterView.this.replyingMessageObject, parent, notify, scheduleDate);
                        MediaDataController.getInstance(ChatActivityEnterView.this.currentAccount).addRecentGif(document, (int) (System.currentTimeMillis() / 1000));
                        if (((int) ChatActivityEnterView.this.dialog_id) == 0) {
                            ChatActivityEnterView.this.accountInstance.getMessagesController().saveGif(parent, document);
                        }
                    } else if (gif instanceof TLRPC.BotInlineResult) {
                        TLRPC.BotInlineResult result = (TLRPC.BotInlineResult) gif;
                        if (result.document != null) {
                            MediaDataController.getInstance(ChatActivityEnterView.this.currentAccount).addRecentGif(result.document, (int) (System.currentTimeMillis() / 1000));
                            if (((int) ChatActivityEnterView.this.dialog_id) == 0) {
                                ChatActivityEnterView.this.accountInstance.getMessagesController().saveGif(parent, result.document);
                            }
                        }
                        HashMap<String, String> params = new HashMap<>();
                        params.put(TtmlNode.ATTR_ID, result.id);
                        params.put("query_id", "" + result.query_id);
                        SendMessagesHelper.prepareSendingBotContextResult(ChatActivityEnterView.this.accountInstance, result, params, ChatActivityEnterView.this.dialog_id, ChatActivityEnterView.this.replyingMessageObject, notify, scheduleDate);
                        if (ChatActivityEnterView.this.searchingType != 0) {
                            ChatActivityEnterView.this.searchingType = 0;
                            ChatActivityEnterView.this.emojiView.closeSearch(true);
                            ChatActivityEnterView.this.emojiView.hideSearchKeyboard();
                        }
                    }
                    if (ChatActivityEnterView.this.delegate != null) {
                        ChatActivityEnterView.this.delegate.onMessageSend(null, notify, scheduleDate);
                        return;
                    }
                    return;
                }
                if (ChatActivityEnterView.this.delegate != null) {
                    ChatActivityEnterView.this.delegate.onUpdateSlowModeButton(view != null ? view : ChatActivityEnterView.this.slowModeButton, true, ChatActivityEnterView.this.slowModeButton.getText());
                    return;
                }
                return;
            }
            AlertsCreator.createScheduleDatePickerDialog(ChatActivityEnterView.this.parentActivity, UserObject.isUserSelf(ChatActivityEnterView.this.parentFragment.getCurrentUser()), new AlertsCreator.ScheduleDatePickerDelegate() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$ChatActivityEnterView$35$EorzHzUKneDjVuQD3YSE0LR_pJk
                @Override // im.uwrkaxlmjj.ui.components.AlertsCreator.ScheduleDatePickerDelegate
                public final void didSelectDate(boolean z, int i) {
                    this.f$0.lambda$onGifSelected$0$ChatActivityEnterView$35(view, gif, parent, z, i);
                }
            });
        }

        @Override // im.uwrkaxlmjj.ui.components.EmojiView.EmojiViewDelegate
        public void onTabOpened(int type) {
            ChatActivityEnterView.this.delegate.onStickersTab(type == 3);
            ChatActivityEnterView chatActivityEnterView = ChatActivityEnterView.this;
            chatActivityEnterView.post(chatActivityEnterView.updateExpandabilityRunnable);
        }

        @Override // im.uwrkaxlmjj.ui.components.EmojiView.EmojiViewDelegate
        public void onClearEmojiRecent() {
            if (ChatActivityEnterView.this.parentFragment == null || ChatActivityEnterView.this.parentActivity == null) {
                return;
            }
            AlertDialog.Builder builder = new AlertDialog.Builder(ChatActivityEnterView.this.parentActivity);
            builder.setTitle(LocaleController.getString("AppName", R.string.AppName));
            builder.setMessage(LocaleController.getString("ClearRecentEmoji", R.string.ClearRecentEmoji));
            builder.setPositiveButton(LocaleController.getString("ClearButton", R.string.ClearButton).toUpperCase(), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$ChatActivityEnterView$35$6fQwkHy_LEjFQEk-_mCDLx7m4I8
                @Override // android.content.DialogInterface.OnClickListener
                public final void onClick(DialogInterface dialogInterface, int i) {
                    this.f$0.lambda$onClearEmojiRecent$1$ChatActivityEnterView$35(dialogInterface, i);
                }
            });
            builder.setNegativeButton(LocaleController.getString("Cancel", R.string.Cancel), null);
            ChatActivityEnterView.this.parentFragment.showDialog(builder.create());
        }

        public /* synthetic */ void lambda$onClearEmojiRecent$1$ChatActivityEnterView$35(DialogInterface dialogInterface, int i) {
            ChatActivityEnterView.this.emojiView.clearRecentEmoji();
        }

        @Override // im.uwrkaxlmjj.ui.components.EmojiView.EmojiViewDelegate
        public void onShowStickerSet(TLRPC.StickerSet stickerSet, TLRPC.InputStickerSet inputStickerSet) {
            if (ChatActivityEnterView.this.parentFragment == null || ChatActivityEnterView.this.parentActivity == null) {
                return;
            }
            if (stickerSet != null) {
                inputStickerSet = new TLRPC.TL_inputStickerSetID();
                inputStickerSet.access_hash = stickerSet.access_hash;
                inputStickerSet.id = stickerSet.id;
            }
            ChatActivityEnterView.this.parentFragment.showDialog(new StickersAlert(ChatActivityEnterView.this.parentActivity, ChatActivityEnterView.this.parentFragment, inputStickerSet, null, ChatActivityEnterView.this));
        }

        @Override // im.uwrkaxlmjj.ui.components.EmojiView.EmojiViewDelegate
        public void onStickerSetAdd(TLRPC.StickerSetCovered stickerSet) {
            MediaDataController.getInstance(ChatActivityEnterView.this.currentAccount).installStickerSet(ChatActivityEnterView.this.parentActivity, 0, stickerSet);
        }

        @Override // im.uwrkaxlmjj.ui.components.EmojiView.EmojiViewDelegate
        public void onStickerSetRemove(TLRPC.StickerSetCovered stickerSet) {
            MediaDataController.getInstance(ChatActivityEnterView.this.currentAccount).removeStickersSet(ChatActivityEnterView.this.parentActivity, stickerSet.set, 1, ChatActivityEnterView.this.parentFragment, false);
        }

        @Override // im.uwrkaxlmjj.ui.components.EmojiView.EmojiViewDelegate
        public void onStickersGroupClick(int chatId) {
            if (ChatActivityEnterView.this.parentFragment != null) {
                if (AndroidUtilities.isTablet()) {
                    ChatActivityEnterView.this.hidePopup(false);
                }
                GroupStickersActivity fragment = new GroupStickersActivity(chatId);
                fragment.setInfo(ChatActivityEnterView.this.info);
                ChatActivityEnterView.this.parentFragment.presentFragment(fragment);
            }
        }

        @Override // im.uwrkaxlmjj.ui.components.EmojiView.EmojiViewDelegate
        public void onSearchOpenClose(int type) {
            ChatActivityEnterView.this.searchingType = type;
            ChatActivityEnterView.this.setStickersExpanded(type != 0, false, false);
            if (ChatActivityEnterView.this.emojiTabOpen && ChatActivityEnterView.this.searchingType == 2) {
                ChatActivityEnterView.this.checkStickresExpandHeight();
            }
        }

        @Override // im.uwrkaxlmjj.ui.components.EmojiView.EmojiViewDelegate
        public boolean isSearchOpened() {
            return ChatActivityEnterView.this.searchingType != 0;
        }

        @Override // im.uwrkaxlmjj.ui.components.EmojiView.EmojiViewDelegate
        public boolean isExpanded() {
            return ChatActivityEnterView.this.stickersExpanded;
        }

        @Override // im.uwrkaxlmjj.ui.components.EmojiView.EmojiViewDelegate
        public boolean canSchedule() {
            return ChatActivityEnterView.this.parentFragment != null && ChatActivityEnterView.this.parentFragment.canScheduleMessage();
        }

        @Override // im.uwrkaxlmjj.ui.components.EmojiView.EmojiViewDelegate
        public boolean isInScheduleMode() {
            return ChatActivityEnterView.this.parentFragment != null && ChatActivityEnterView.this.parentFragment.isInScheduleMode();
        }
    }

    private void createMenuView() {
        String str;
        EnterMenuView enterMenuView = this.menuView;
        if (enterMenuView != null) {
            ChatActivity chatActivity = this.parentFragment;
            enterMenuView.setCurrentChat(chatActivity != null ? chatActivity.getCurrentChat() : null);
            return;
        }
        long j = this.dialog_id;
        int lower_id = (int) j;
        int high_id = (int) (j >> 32);
        ArrayList<ChatEnterMenuType> chatEnterMenuTypes = new ArrayList<>();
        ArrayList<Integer> chatEnterMenuIcons = new ArrayList<>();
        ArrayList<String> chatEnterMenuTexts = new ArrayList<>();
        ChatActivity chatActivity2 = this.parentFragment;
        if (chatActivity2 != null) {
            chatActivity2.getCurrentEncryptedChat();
        }
        if ((lower_id == 0 && high_id != 0) || lower_id > 0) {
            if (lower_id == 333000 || lower_id == 777000 || lower_id == 42777 || lower_id == UserConfig.getInstance(UserConfig.selectedAccount).clientUserId) {
                chatEnterMenuTexts.add(LocaleController.getString("chat_choose_photos", R.string.chat_choose_photos));
                chatEnterMenuTexts.add(LocaleController.getString("chat_take_photo", R.string.chat_take_photo));
                chatEnterMenuIcons.add(Integer.valueOf(R.drawable.selector_chat_attach_menu_album));
                chatEnterMenuIcons.add(Integer.valueOf(R.drawable.selector_chat_attach_menu_camera));
                chatEnterMenuTypes.add(ChatEnterMenuType.ALBUM);
                chatEnterMenuTypes.add(ChatEnterMenuType.CAMERA);
            } else {
                boolean showRdp = BuildVars.WALLET_RED_PACKET_ENABLE;
                chatEnterMenuTexts.add(LocaleController.getString("chat_choose_photos", R.string.chat_choose_photos));
                chatEnterMenuTexts.add(LocaleController.getString("chat_take_photo", R.string.chat_take_photo));
                chatEnterMenuTexts.add(LocaleController.getString("ChatVideo", R.string.ChatVideo));
                chatEnterMenuTexts.add(LocaleController.getString("visual_call_voice", R.string.visual_call_voice));
                if (showRdp) {
                    chatEnterMenuTexts.add(LocaleController.getString("Transfer", R.string.Transfer));
                    chatEnterMenuTexts.add(LocaleController.getString("RedPacket", R.string.RedPacket));
                }
                chatEnterMenuIcons.add(Integer.valueOf(R.drawable.selector_chat_attach_menu_album));
                chatEnterMenuIcons.add(Integer.valueOf(R.drawable.selector_chat_attach_menu_camera));
                chatEnterMenuIcons.add(Integer.valueOf(R.drawable.selector_chat_attach_menu_video));
                chatEnterMenuIcons.add(Integer.valueOf(R.drawable.selector_chat_attach_menu_voice));
                if (showRdp) {
                    chatEnterMenuIcons.add(Integer.valueOf(R.drawable.selector_chat_attach_menu_transfer));
                    chatEnterMenuIcons.add(Integer.valueOf(R.drawable.selector_chat_attach_menu_hongbao));
                }
                chatEnterMenuTypes.add(ChatEnterMenuType.ALBUM);
                chatEnterMenuTypes.add(ChatEnterMenuType.CAMERA);
                chatEnterMenuTypes.add(ChatEnterMenuType.VIDEOCALL);
                chatEnterMenuTypes.add(ChatEnterMenuType.VOICECALL);
                if (showRdp) {
                    chatEnterMenuTypes.add(ChatEnterMenuType.TRANSFER);
                    chatEnterMenuTypes.add(ChatEnterMenuType.REDPACKET);
                }
            }
        } else {
            boolean isChannel = false;
            boolean z = false;
            if (((int) this.dialog_id) < 0) {
                str = "RedPacket";
                TLRPC.Chat chat = this.accountInstance.getMessagesController().getChat(Integer.valueOf(-((int) this.dialog_id)));
                isChannel = ChatObject.isChannel(chat) && !chat.megagroup;
                ChatObject.hasAdminRights(chat);
            } else {
                str = "RedPacket";
            }
            if (BuildVars.WALLET_ENABLE && !isChannel) {
                z = true;
            }
            boolean showRedpacket = z;
            chatEnterMenuTexts.add(LocaleController.getString("chat_choose_photos", R.string.chat_choose_photos));
            chatEnterMenuTexts.add(LocaleController.getString("chat_take_photo", R.string.chat_take_photo));
            if (showRedpacket) {
                chatEnterMenuTexts.add(LocaleController.getString(str, R.string.RedPacket));
            }
            chatEnterMenuTexts.add(LocaleController.getString("Poll", R.string.Poll));
            if (0 != 0) {
                chatEnterMenuTexts.add(LocaleController.getString(R.string.live_group_title));
            }
            chatEnterMenuIcons.add(Integer.valueOf(R.drawable.selector_chat_attach_menu_album));
            chatEnterMenuIcons.add(Integer.valueOf(R.drawable.selector_chat_attach_menu_camera));
            if (showRedpacket) {
                chatEnterMenuIcons.add(Integer.valueOf(R.drawable.selector_chat_attach_menu_hongbao));
            }
            chatEnterMenuIcons.add(Integer.valueOf(R.drawable.selector_chat_attach_menu_poll));
            if (0 != 0) {
                chatEnterMenuIcons.add(Integer.valueOf(R.drawable.selector_chat_attach_menu_live));
            }
            chatEnterMenuTypes.add(ChatEnterMenuType.ALBUM);
            chatEnterMenuTypes.add(ChatEnterMenuType.CAMERA);
            if (showRedpacket) {
                chatEnterMenuTypes.add(ChatEnterMenuType.REDPACKET);
            }
            chatEnterMenuTypes.add(ChatEnterMenuType.POLL);
            if (0 != 0) {
                chatEnterMenuTypes.add(ChatEnterMenuType.GROUP_LIVE);
            }
        }
        this.attachTexts.addAll(chatEnterMenuTexts);
        this.attachIcons.addAll(chatEnterMenuIcons);
        this.attachTypes.addAll(chatEnterMenuTypes);
        EnterMenuView enterMenuView2 = new EnterMenuView(this.parentActivity);
        this.menuView = enterMenuView2;
        enterMenuView2.setVisibility(8);
        this.menuView.setDelegate(new EnterMenuView.EnterMenuViewDelegate() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$ChatActivityEnterView$u7mAhnSVQFizPwnvgDgp6k094rQ
            @Override // im.uwrkaxlmjj.ui.components.EnterMenuView.EnterMenuViewDelegate
            public final void onItemClie(int i, ChatEnterMenuType chatEnterMenuType) {
                this.f$0.lambda$createMenuView$27$ChatActivityEnterView(i, chatEnterMenuType);
            }
        });
        this.menuView.setDataAndNotify(this.attachTexts, this.attachIcons, this.attachTypes);
        EnterMenuView enterMenuView3 = this.menuView;
        ChatActivity chatActivity3 = this.parentFragment;
        enterMenuView3.setCurrentChat(chatActivity3 != null ? chatActivity3.getCurrentChat() : null);
        SizeNotifierFrameLayout sizeNotifierFrameLayout = this.sizeNotifierLayout;
        sizeNotifierFrameLayout.addView(this.menuView, sizeNotifierFrameLayout.getChildCount() - 1, LayoutHelper.createFrame(-1, -1, 17));
    }

    public /* synthetic */ void lambda$createMenuView$27$ChatActivityEnterView(int position, ChatEnterMenuType menuType) {
        ChatActivityEnterViewDelegate chatActivityEnterViewDelegate = this.delegate;
        if (chatActivityEnterViewDelegate != null) {
            chatActivityEnterViewDelegate.didPressedAttachButton(position, menuType);
        }
    }

    @Override // im.uwrkaxlmjj.ui.components.StickersAlert.StickersAlertDelegate
    /* JADX INFO: renamed from: onStickerSelected, reason: merged with bridge method [inline-methods] */
    public void lambda$onStickerSelected$28$ChatActivityEnterView(final TLRPC.Document sticker, final Object parent, final boolean clearsInputField, boolean notify, int scheduleDate) {
        if (isInScheduleMode() && scheduleDate == 0) {
            AlertsCreator.createScheduleDatePickerDialog(this.parentActivity, UserObject.isUserSelf(this.parentFragment.getCurrentUser()), new AlertsCreator.ScheduleDatePickerDelegate() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$ChatActivityEnterView$FhlZlaYVuO5P3NjbSKJpwElhJiU
                @Override // im.uwrkaxlmjj.ui.components.AlertsCreator.ScheduleDatePickerDelegate
                public final void didSelectDate(boolean z, int i) {
                    this.f$0.lambda$onStickerSelected$28$ChatActivityEnterView(sticker, parent, clearsInputField, z, i);
                }
            });
            return;
        }
        if (this.slowModeTimer > 0 && !isInScheduleMode()) {
            ChatActivityEnterViewDelegate chatActivityEnterViewDelegate = this.delegate;
            if (chatActivityEnterViewDelegate != null) {
                SimpleTextView simpleTextView = this.slowModeButton;
                chatActivityEnterViewDelegate.onUpdateSlowModeButton(simpleTextView, true, simpleTextView.getText());
                return;
            }
            return;
        }
        if (this.searchingType != 0) {
            this.searchingType = 0;
            this.emojiView.closeSearch(true);
            this.emojiView.hideSearchKeyboard();
        }
        setStickersExpanded(false, true, false);
        SendMessagesHelper.getInstance(this.currentAccount).sendSticker(sticker, this.dialog_id, this.replyingMessageObject, parent, notify, scheduleDate);
        ChatActivityEnterViewDelegate chatActivityEnterViewDelegate2 = this.delegate;
        if (chatActivityEnterViewDelegate2 != null) {
            chatActivityEnterViewDelegate2.onMessageSend(null, true, scheduleDate);
        }
        if (clearsInputField) {
            setFieldText("");
        }
        MediaDataController.getInstance(this.currentAccount).addRecentSticker(0, parent, sticker, (int) (System.currentTimeMillis() / 1000), false);
    }

    @Override // im.uwrkaxlmjj.ui.components.StickersAlert.StickersAlertDelegate
    public boolean canSchedule() {
        ChatActivity chatActivity = this.parentFragment;
        return chatActivity != null && chatActivity.canScheduleMessage();
    }

    @Override // im.uwrkaxlmjj.ui.components.StickersAlert.StickersAlertDelegate
    public boolean isInScheduleMode() {
        ChatActivity chatActivity = this.parentFragment;
        return chatActivity != null && chatActivity.isInScheduleMode();
    }

    public void addStickerToRecent(TLRPC.Document sticker) {
        createEmojiView();
        this.emojiView.addRecentSticker(sticker);
    }

    public void hideEmojiView() {
        EmojiView emojiView;
        if (!this.emojiViewVisible && (emojiView = this.emojiView) != null && emojiView.getVisibility() != 8) {
            this.sizeNotifierLayout.removeView(this.emojiView);
            this.emojiView.setVisibility(8);
        }
    }

    private void showAttachMenu() {
    }

    public void showEmojiView() {
        showPopup(1, 0);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void showPopup(int show, int contentType) {
        Log.d("bond", "show  = " + show + "------ contentType = " + contentType);
        if (show == 1) {
            if (contentType == 0 && this.emojiView == null) {
                if (this.parentActivity == null) {
                    return;
                } else {
                    createEmojiView();
                }
            }
            View currentView = null;
            if (contentType == 0) {
                if (this.emojiView.getParent() == null) {
                    SizeNotifierFrameLayout sizeNotifierFrameLayout = this.sizeNotifierLayout;
                    sizeNotifierFrameLayout.addView(this.emojiView, sizeNotifierFrameLayout.getChildCount() - 1);
                }
                this.emojiView.setVisibility(0);
                this.emojiViewVisible = true;
                BotKeyboardView botKeyboardView = this.botKeyboardView;
                if (botKeyboardView != null && botKeyboardView.getVisibility() != 8) {
                    this.botKeyboardView.setVisibility(8);
                }
                EnterMenuView enterMenuView = this.menuView;
                if (enterMenuView != null && enterMenuView.getVisibility() != 8) {
                    this.sizeNotifierLayout.removeView(this.menuView);
                    this.menuView.setVisibility(8);
                    this.menuViewVisible = false;
                }
                currentView = this.emojiView;
            } else if (contentType == 1) {
                EmojiView emojiView = this.emojiView;
                if (emojiView != null && emojiView.getVisibility() != 8) {
                    this.sizeNotifierLayout.removeView(this.emojiView);
                    this.emojiView.setVisibility(8);
                    this.emojiViewVisible = false;
                }
                EnterMenuView enterMenuView2 = this.menuView;
                if (enterMenuView2 != null && enterMenuView2.getVisibility() != 8) {
                    this.sizeNotifierLayout.removeView(this.menuView);
                    this.menuView.setVisibility(8);
                    this.menuViewVisible = false;
                }
                this.botKeyboardView.setVisibility(0);
                currentView = this.botKeyboardView;
            }
            this.currentPopupContentType = contentType;
            if (this.keyboardHeight <= 0) {
                this.keyboardHeight = MessagesController.getGlobalEmojiSettings().getInt("kbd_height", AndroidUtilities.dp(236.0f));
            }
            if (this.keyboardHeightLand <= 0) {
                this.keyboardHeightLand = MessagesController.getGlobalEmojiSettings().getInt("kbd_height_land3", AndroidUtilities.dp(236.0f));
            }
            int currentHeight = AndroidUtilities.displaySize.x > AndroidUtilities.displaySize.y ? this.keyboardHeightLand : this.keyboardHeight;
            if (contentType == 1) {
                currentHeight = Math.min(this.botKeyboardView.getKeyboardHeight(), currentHeight);
            }
            BotKeyboardView botKeyboardView2 = this.botKeyboardView;
            if (botKeyboardView2 != null) {
                botKeyboardView2.setPanelHeight(currentHeight);
            }
            FrameLayout.LayoutParams layoutParams = (FrameLayout.LayoutParams) currentView.getLayoutParams();
            layoutParams.height = currentHeight;
            currentView.setLayoutParams(layoutParams);
            if (!AndroidUtilities.isInMultiwindow) {
                AndroidUtilities.hideKeyboard(this.messageEditText);
            }
            SizeNotifierFrameLayout sizeNotifierFrameLayout2 = this.sizeNotifierLayout;
            if (sizeNotifierFrameLayout2 != null) {
                this.emojiPadding = currentHeight;
                sizeNotifierFrameLayout2.requestLayout();
                setEmojiButtonImage(true, true);
                updateBotButton();
                onWindowSizeChanged();
            }
        } else if (show == 3) {
            if (contentType == 3 && this.menuView == null) {
                if (this.parentActivity == null) {
                    return;
                } else {
                    createMenuView();
                }
            }
            EnterMenuView enterMenuView3 = this.menuView;
            if (enterMenuView3 != null) {
                ChatActivity chatActivity = this.parentFragment;
                enterMenuView3.setCurrentChat(chatActivity != null ? chatActivity.getCurrentChat() : null);
            }
            View currentView2 = null;
            if (contentType == 3) {
                if (this.menuView.getParent() == null) {
                    SizeNotifierFrameLayout sizeNotifierFrameLayout3 = this.sizeNotifierLayout;
                    sizeNotifierFrameLayout3.addView(this.menuView, sizeNotifierFrameLayout3.getChildCount() - 1, LayoutHelper.createFrame(-2, -2, 1));
                }
                this.menuView.setVisibility(0);
                this.menuViewVisible = true;
                BotKeyboardView botKeyboardView3 = this.botKeyboardView;
                if (botKeyboardView3 != null && botKeyboardView3.getVisibility() != 8) {
                    this.botKeyboardView.setVisibility(8);
                }
                EmojiView emojiView2 = this.emojiView;
                if (emojiView2 != null && emojiView2.getVisibility() != 8) {
                    this.sizeNotifierLayout.removeView(this.emojiView);
                    this.emojiView.setVisibility(8);
                    this.emojiViewVisible = false;
                }
                currentView2 = this.menuView;
            }
            this.currentPopupContentType = contentType;
            if (this.keyboardHeight <= 0) {
                this.keyboardHeight = MessagesController.getGlobalEmojiSettings().getInt("kbd_height", AndroidUtilities.dp(236.0f));
            }
            if (this.keyboardHeightLand <= 0) {
                this.keyboardHeightLand = MessagesController.getGlobalEmojiSettings().getInt("kbd_height_land3", AndroidUtilities.dp(236.0f));
            }
            int currentHeight2 = AndroidUtilities.displaySize.x > AndroidUtilities.displaySize.y ? this.keyboardHeightLand : this.keyboardHeight;
            if (contentType == 1) {
                currentHeight2 = Math.min(this.botKeyboardView.getKeyboardHeight(), currentHeight2);
            }
            BotKeyboardView botKeyboardView4 = this.botKeyboardView;
            if (botKeyboardView4 != null) {
                botKeyboardView4.setPanelHeight(currentHeight2);
            }
            FrameLayout.LayoutParams layoutParams2 = (FrameLayout.LayoutParams) currentView2.getLayoutParams();
            layoutParams2.height = currentHeight2;
            currentView2.setLayoutParams(layoutParams2);
            if (!AndroidUtilities.isInMultiwindow) {
                AndroidUtilities.hideKeyboard(this.messageEditText);
            }
            SizeNotifierFrameLayout sizeNotifierFrameLayout4 = this.sizeNotifierLayout;
            if (sizeNotifierFrameLayout4 != null) {
                this.emojiPadding = currentHeight2;
                sizeNotifierFrameLayout4.requestLayout();
                updateBotButton();
                onWindowSizeChanged();
            }
        } else {
            if (this.emojiButton != null) {
                setEmojiButtonImage(false, true);
            }
            this.currentPopupContentType = -1;
            if (this.emojiView != null) {
                this.emojiViewVisible = false;
                if (show == 2 || AndroidUtilities.usingHardwareInput || AndroidUtilities.isInMultiwindow) {
                    this.sizeNotifierLayout.removeView(this.emojiView);
                    this.emojiView.setVisibility(8);
                }
            }
            if (this.menuView != null) {
                this.menuViewVisible = false;
                if (show != 3 || AndroidUtilities.usingHardwareInput || AndroidUtilities.isInMultiwindow) {
                    this.sizeNotifierLayout.removeView(this.menuView);
                    this.menuView.setVisibility(8);
                }
            }
            BotKeyboardView botKeyboardView5 = this.botKeyboardView;
            if (botKeyboardView5 != null) {
                botKeyboardView5.setVisibility(8);
            }
            if (this.sizeNotifierLayout != null) {
                if (show == 0) {
                    this.emojiPadding = 0;
                }
                this.sizeNotifierLayout.requestLayout();
                onWindowSizeChanged();
            }
            updateBotButton();
        }
        if (this.stickersTabOpen || this.emojiTabOpen) {
            checkSendButton(true);
        }
        if (this.stickersExpanded && show != 1) {
            setStickersExpanded(false, false, false);
        }
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r13v1 */
    /* JADX WARN: Type inference failed for: r13v2 */
    /* JADX WARN: Type inference failed for: r13v3 */
    /* JADX WARN: Type inference failed for: r13v4 */
    private void setEmojiButtonImage(boolean z, boolean z2) {
        int currentPage;
        int i;
        ?? r13 = z2;
        if (z2) {
            r13 = z2;
            if (this.currentEmojiIcon == -1) {
                r13 = 0;
            }
        }
        if (z && this.currentPopupContentType == 0) {
            i = 0;
        } else {
            EmojiView emojiView = this.emojiView;
            if (emojiView == null) {
                currentPage = MessagesController.getGlobalEmojiSettings().getInt("selected_page", 0);
            } else {
                currentPage = emojiView.getCurrentPage();
            }
            if (currentPage == 0 || (!this.allowStickers && !this.allowGifs)) {
                i = 1;
            } else if (currentPage == 1) {
                i = 2;
            } else {
                i = 3;
            }
        }
        if (this.currentEmojiIcon == i) {
            return;
        }
        AnimatorSet animatorSet = this.emojiButtonAnimation;
        if (animatorSet != null) {
            animatorSet.cancel();
            this.emojiButtonAnimation = null;
        }
        if (i == 0) {
            this.emojiButton[r13].setImageResource(R.drawable.input_keyboard);
        } else if (i == 1) {
            this.emojiButton[r13].setImageResource(R.drawable.input_smile2);
        } else if (i == 2) {
            this.emojiButton[r13].setImageResource(R.drawable.input_sticker);
        } else if (i == 3) {
            this.emojiButton[r13].setImageResource(R.drawable.input_gif);
        }
        this.emojiButton[r13].setTag(i == 2 ? 1 : null);
        this.currentEmojiIcon = i;
        if (r13 != 0) {
            this.emojiButton[1].setVisibility(0);
            AnimatorSet animatorSet2 = new AnimatorSet();
            this.emojiButtonAnimation = animatorSet2;
            animatorSet2.playTogether(ObjectAnimator.ofFloat(this.emojiButton[0], (Property<ImageView, Float>) View.SCALE_X, 0.1f), ObjectAnimator.ofFloat(this.emojiButton[0], (Property<ImageView, Float>) View.SCALE_Y, 0.1f), ObjectAnimator.ofFloat(this.emojiButton[0], (Property<ImageView, Float>) View.ALPHA, 0.0f), ObjectAnimator.ofFloat(this.emojiButton[1], (Property<ImageView, Float>) View.SCALE_X, 1.0f), ObjectAnimator.ofFloat(this.emojiButton[1], (Property<ImageView, Float>) View.SCALE_Y, 1.0f), ObjectAnimator.ofFloat(this.emojiButton[1], (Property<ImageView, Float>) View.ALPHA, 1.0f));
            this.emojiButtonAnimation.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.components.ChatActivityEnterView.37
                @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                public void onAnimationEnd(Animator animation) {
                    if (animation.equals(ChatActivityEnterView.this.emojiButtonAnimation)) {
                        ChatActivityEnterView.this.emojiButtonAnimation = null;
                        ImageView temp = ChatActivityEnterView.this.emojiButton[1];
                        ChatActivityEnterView.this.emojiButton[1] = ChatActivityEnterView.this.emojiButton[0];
                        ChatActivityEnterView.this.emojiButton[0] = temp;
                        ChatActivityEnterView.this.emojiButton[1].setVisibility(4);
                        ChatActivityEnterView.this.emojiButton[1].setAlpha(0.0f);
                        ChatActivityEnterView.this.emojiButton[1].setScaleX(0.1f);
                        ChatActivityEnterView.this.emojiButton[1].setScaleY(0.1f);
                    }
                }
            });
            this.emojiButtonAnimation.setDuration(150L);
            this.emojiButtonAnimation.start();
        }
    }

    public void hidePopup(boolean byBackButton) {
        if (isPopupShowing()) {
            if (this.currentPopupContentType == 1 && byBackButton && this.botButtonsMessageObject != null) {
                SharedPreferences preferences = MessagesController.getMainSettings(this.currentAccount);
                preferences.edit().putInt("hidekeyboard_" + this.dialog_id, this.botButtonsMessageObject.getId()).commit();
            }
            if (byBackButton && this.searchingType != 0) {
                this.searchingType = 0;
                this.emojiView.closeSearch(true);
                this.messageEditText.requestFocus();
                setStickersExpanded(false, true, false);
                if (this.emojiTabOpen) {
                    checkSendButton(true);
                    return;
                }
                return;
            }
            if (this.searchingType != 0) {
                this.searchingType = 0;
                this.emojiView.closeSearch(false);
                this.messageEditText.requestFocus();
            }
            showPopup(0, 0);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void openKeyboardInternal() {
        showPopup((AndroidUtilities.usingHardwareInput || this.isPaused) ? 0 : 2, 0);
        this.messageEditText.requestFocus();
        AndroidUtilities.showKeyboard(this.messageEditText);
        if (this.isPaused) {
            this.showKeyboardOnResume = true;
            return;
        }
        if (!AndroidUtilities.usingHardwareInput && !this.keyboardVisible && !AndroidUtilities.isInMultiwindow) {
            this.waitingForKeyboardOpen = true;
            AndroidUtilities.cancelRunOnUIThread(this.openKeyboardRunnable);
            AndroidUtilities.runOnUIThread(this.openKeyboardRunnable, 100L);
        }
    }

    public boolean isEditingMessage() {
        return this.editingMessageObject != null;
    }

    public MessageObject getEditingMessageObject() {
        return this.editingMessageObject;
    }

    public boolean isEditingCaption() {
        return this.editingCaption;
    }

    public boolean hasAudioToSend() {
        return (this.audioToSendMessageObject == null && this.videoToSendMessageObject == null) ? false : true;
    }

    public void openKeyboard() {
        AndroidUtilities.showKeyboard(this.messageEditText);
    }

    public void closeKeyboard() {
        AndroidUtilities.hideKeyboard(this.messageEditText);
    }

    public boolean isPopupShowing() {
        BotKeyboardView botKeyboardView;
        return this.emojiViewVisible || this.menuViewVisible || ((botKeyboardView = this.botKeyboardView) != null && botKeyboardView.getVisibility() == 0);
    }

    public boolean isKeyboardVisible() {
        return this.keyboardVisible;
    }

    public void addRecentGif(TLRPC.Document searchImage) {
        MediaDataController.getInstance(this.currentAccount).addRecentGif(searchImage, (int) (System.currentTimeMillis() / 1000));
        EmojiView emojiView = this.emojiView;
        if (emojiView != null) {
            emojiView.addRecentGif(searchImage);
        }
    }

    public void removeRecentGif(TLRPC.Document searchImage) {
        MediaDataController.getInstance(this.currentAccount).removeRecentGifById(searchImage);
        EmojiView emojiView = this.emojiView;
        if (emojiView != null) {
            emojiView.removeRecentGif(searchImage);
        }
    }

    @Override // android.view.View
    protected void onSizeChanged(int w, int h, int oldw, int oldh) {
        super.onSizeChanged(w, h, oldw, oldh);
        if (w != oldw && this.stickersExpanded) {
            this.searchingType = 0;
            this.emojiView.closeSearch(false);
            setStickersExpanded(false, false, false);
        }
        this.videoTimelineView.clearFrames();
    }

    public boolean isStickersExpanded() {
        return this.stickersExpanded;
    }

    @Override // im.uwrkaxlmjj.ui.components.SizeNotifierFrameLayout.SizeNotifierFrameLayoutDelegate
    public void onSizeChanged(int height, boolean isWidthGreater) {
        boolean z;
        if (this.searchingType != 0) {
            this.lastSizeChangeValue1 = height;
            this.lastSizeChangeValue2 = isWidthGreater;
            this.keyboardVisible = height > 0;
            return;
        }
        if (height > AndroidUtilities.dp(50.0f) && this.keyboardVisible && !AndroidUtilities.isInMultiwindow) {
            if (isWidthGreater) {
                this.keyboardHeightLand = height;
                MessagesController.getGlobalEmojiSettings().edit().putInt("kbd_height_land3", this.keyboardHeightLand).commit();
            } else {
                this.keyboardHeight = height;
                MessagesController.getGlobalEmojiSettings().edit().putInt("kbd_height", this.keyboardHeight).commit();
            }
        }
        if (isPopupShowing()) {
            int newHeight = isWidthGreater ? this.keyboardHeightLand : this.keyboardHeight;
            if (this.currentPopupContentType == 1 && !this.botKeyboardView.isFullSize()) {
                newHeight = Math.min(this.botKeyboardView.getKeyboardHeight(), newHeight);
            }
            View currentView = null;
            int i = this.currentPopupContentType;
            if (i == 0) {
                currentView = this.emojiView;
            } else if (i == 1) {
                currentView = this.botKeyboardView;
            } else if (i == 3) {
                currentView = this.menuView;
            }
            BotKeyboardView botKeyboardView = this.botKeyboardView;
            if (botKeyboardView != null) {
                botKeyboardView.setPanelHeight(newHeight);
            }
            FrameLayout.LayoutParams layoutParams = (FrameLayout.LayoutParams) currentView.getLayoutParams();
            if (!this.closeAnimationInProgress && ((layoutParams.width != AndroidUtilities.displaySize.x || layoutParams.height != newHeight) && !this.stickersExpanded)) {
                layoutParams.width = AndroidUtilities.displaySize.x;
                layoutParams.height = newHeight;
                currentView.setLayoutParams(layoutParams);
                if (this.sizeNotifierLayout != null) {
                    this.emojiPadding = layoutParams.height;
                    this.sizeNotifierLayout.requestLayout();
                    onWindowSizeChanged();
                }
            }
        }
        if (this.lastSizeChangeValue1 == height && this.lastSizeChangeValue2 == isWidthGreater) {
            onWindowSizeChanged();
            return;
        }
        this.lastSizeChangeValue1 = height;
        this.lastSizeChangeValue2 = isWidthGreater;
        boolean oldValue = this.keyboardVisible;
        boolean z2 = height > 0;
        this.keyboardVisible = z2;
        if (z2 && isPopupShowing()) {
            showPopup(0, this.currentPopupContentType);
        }
        if (this.emojiPadding != 0 && !(z = this.keyboardVisible) && z != oldValue && !isPopupShowing()) {
            this.emojiPadding = 0;
            this.sizeNotifierLayout.requestLayout();
        }
        if (this.keyboardVisible && this.waitingForKeyboardOpen) {
            this.waitingForKeyboardOpen = false;
            AndroidUtilities.cancelRunOnUIThread(this.openKeyboardRunnable);
        }
        onWindowSizeChanged();
    }

    public int getEmojiPadding() {
        return this.emojiPadding;
    }

    @Override // im.uwrkaxlmjj.messenger.NotificationCenter.NotificationCenterDelegate
    public void didReceivedNotification(int id, int account, Object... args) {
        TLRPC.ChatFull chatFull;
        TLRPC.Chat chat;
        if (id == NotificationCenter.emojiDidLoad) {
            EmojiView emojiView = this.emojiView;
            if (emojiView != null) {
                emojiView.invalidateViews();
            }
            BotKeyboardView botKeyboardView = this.botKeyboardView;
            if (botKeyboardView != null) {
                botKeyboardView.invalidateViews();
                return;
            }
            return;
        }
        if (id == NotificationCenter.recordProgressChanged) {
            int guid = ((Integer) args[0]).intValue();
            if (guid != this.recordingGuid) {
                return;
            }
            long t = ((Long) args[1]).longValue();
            long time = t / 1000;
            int ms = ((int) (t % 1000)) / 10;
            String str = String.format("%02d:%02d.%02d", Long.valueOf(time / 60), Long.valueOf(time % 60), Integer.valueOf(ms));
            String str2 = this.lastTimeString;
            if (str2 == null || !str2.equals(str)) {
                if (this.lastTypingSendTime != time && time % 5 == 0 && !isInScheduleMode()) {
                    this.lastTypingSendTime = time;
                    MessagesController messagesController = this.accountInstance.getMessagesController();
                    long j = this.dialog_id;
                    ImageView imageView = this.videoSendButton;
                    messagesController.sendTyping(j, (imageView == null || imageView.getTag() == null) ? 1 : 7, 0);
                }
                TextView textView = this.recordTimeText;
                if (textView != null) {
                    textView.setText(str);
                }
            }
            RecordCircle recordCircle = this.recordCircle;
            if (recordCircle != null) {
                recordCircle.setAmplitude(((Double) args[2]).doubleValue());
            }
            ImageView imageView2 = this.videoSendButton;
            if (imageView2 != null && imageView2.getTag() != null && t >= 59500) {
                this.startedDraggingX = -1.0f;
                this.delegate.needStartRecordVideo(3, true, 0);
                return;
            }
            return;
        }
        if (id == NotificationCenter.closeChats) {
            EditTextCaption editTextCaption = this.messageEditText;
            if (editTextCaption != null && editTextCaption.isFocused()) {
                AndroidUtilities.hideKeyboard(this.messageEditText);
                return;
            }
            return;
        }
        if (id == NotificationCenter.recordStartError || id == NotificationCenter.recordStopped) {
            int guid2 = ((Integer) args[0]).intValue();
            if (guid2 != this.recordingGuid) {
                return;
            }
            if (this.recordingAudioVideo) {
                this.accountInstance.getMessagesController().sendTyping(this.dialog_id, 2, 0);
                this.recordingAudioVideo = false;
                updateRecordIntefrace();
            }
            if (id == NotificationCenter.recordStopped) {
                Integer reason = (Integer) args[1];
                if (reason.intValue() == 2) {
                    this.videoTimelineView.setVisibility(0);
                    this.recordedAudioBackground.setVisibility(8);
                    this.recordedAudioTimeTextView.setVisibility(8);
                    this.recordedAudioPlayButton.setVisibility(8);
                    this.recordedAudioSeekBar.setVisibility(8);
                    this.recordedAudioPanel.setAlpha(1.0f);
                    this.recordedAudioPanel.setVisibility(0);
                    return;
                }
                reason.intValue();
                return;
            }
            return;
        }
        if (id == NotificationCenter.recordStarted) {
            int guid3 = ((Integer) args[0]).intValue();
            if (guid3 == this.recordingGuid && !this.recordingAudioVideo) {
                this.recordingAudioVideo = true;
                updateRecordIntefrace();
                return;
            }
            return;
        }
        if (id == NotificationCenter.audioDidSent) {
            int guid4 = ((Integer) args[0]).intValue();
            if (guid4 != this.recordingGuid) {
                return;
            }
            Object audio = args[1];
            if (audio instanceof VideoEditedInfo) {
                this.videoToSendMessageObject = (VideoEditedInfo) audio;
                String str3 = (String) args[2];
                this.audioToSendPath = str3;
                this.videoTimelineView.setVideoPath(str3);
                this.videoTimelineView.setVisibility(0);
                this.videoTimelineView.setMinProgressDiff(1000.0f / this.videoToSendMessageObject.estimatedDuration);
                this.recordedAudioBackground.setVisibility(8);
                this.recordedAudioTimeTextView.setVisibility(8);
                this.recordedAudioPlayButton.setVisibility(8);
                this.recordedAudioSeekBar.setVisibility(8);
                this.recordedAudioPanel.setAlpha(1.0f);
                this.recordedAudioPanel.setVisibility(0);
                closeKeyboard();
                hidePopup(false);
                checkSendButton(false);
                return;
            }
            TLRPC.TL_document tL_document = (TLRPC.TL_document) args[1];
            this.audioToSend = tL_document;
            this.audioToSendPath = (String) args[2];
            if (tL_document != null) {
                if (this.recordedAudioPanel == null) {
                    return;
                }
                this.videoTimelineView.setVisibility(8);
                this.recordedAudioBackground.setVisibility(0);
                this.recordedAudioTimeTextView.setVisibility(0);
                this.recordedAudioPlayButton.setVisibility(0);
                this.recordedAudioSeekBar.setVisibility(0);
                TLRPC.TL_message message = new TLRPC.TL_message();
                message.out = true;
                message.id = 0;
                message.to_id = new TLRPC.TL_peerUser();
                TLRPC.Peer peer = message.to_id;
                int clientUserId = UserConfig.getInstance(this.currentAccount).getClientUserId();
                message.from_id = clientUserId;
                peer.user_id = clientUserId;
                message.date = (int) (System.currentTimeMillis() / 1000);
                message.message = "";
                message.attachPath = this.audioToSendPath;
                message.media = new TLRPC.TL_messageMediaDocument();
                message.media.flags |= 3;
                message.media.document = this.audioToSend;
                message.flags |= 768;
                this.audioToSendMessageObject = new MessageObject(UserConfig.selectedAccount, message, false);
                this.recordedAudioPanel.setAlpha(1.0f);
                this.recordedAudioPanel.setVisibility(0);
                int duration = 0;
                int a = 0;
                while (true) {
                    if (a >= this.audioToSend.attributes.size()) {
                        break;
                    }
                    TLRPC.DocumentAttribute attribute = this.audioToSend.attributes.get(a);
                    if (!(attribute instanceof TLRPC.TL_documentAttributeAudio)) {
                        a++;
                    } else {
                        duration = attribute.duration;
                        break;
                    }
                }
                int a2 = 0;
                while (true) {
                    if (a2 >= this.audioToSend.attributes.size()) {
                        break;
                    }
                    TLRPC.DocumentAttribute attribute2 = this.audioToSend.attributes.get(a2);
                    if (!(attribute2 instanceof TLRPC.TL_documentAttributeAudio)) {
                        a2++;
                    } else {
                        if (attribute2.waveform == null || attribute2.waveform.length == 0) {
                            attribute2.waveform = MediaController.getInstance().getWaveform(this.audioToSendPath);
                        }
                        this.recordedAudioSeekBar.setWaveform(attribute2.waveform);
                    }
                }
                this.recordedAudioTimeTextView.setText(String.format("%d:%02d", Integer.valueOf(duration / 60), Integer.valueOf(duration % 60)));
                closeKeyboard();
                hidePopup(false);
                checkSendButton(false);
                return;
            }
            ChatActivityEnterViewDelegate chatActivityEnterViewDelegate = this.delegate;
            if (chatActivityEnterViewDelegate != null) {
                chatActivityEnterViewDelegate.onMessageSend(null, true, 0);
                return;
            }
            return;
        }
        if (id == NotificationCenter.audioRouteChanged) {
            if (this.parentActivity != null) {
                boolean frontSpeaker = ((Boolean) args[0]).booleanValue();
                this.parentActivity.setVolumeControlStream(frontSpeaker ? 0 : Integer.MIN_VALUE);
                return;
            }
            return;
        }
        if (id == NotificationCenter.messagePlayingDidReset) {
            if (this.audioToSendMessageObject != null && !MediaController.getInstance().isPlayingMessage(this.audioToSendMessageObject)) {
                this.recordedAudioPlayButton.setImageDrawable(this.playDrawable);
                this.recordedAudioPlayButton.setContentDescription(LocaleController.getString("AccActionPlay", R.string.AccActionPlay));
                this.recordedAudioSeekBar.setProgress(0.0f);
                return;
            }
            return;
        }
        if (id == NotificationCenter.messagePlayingProgressDidChanged) {
            if (this.audioToSendMessageObject != null && MediaController.getInstance().isPlayingMessage(this.audioToSendMessageObject)) {
                MessageObject player = MediaController.getInstance().getPlayingMessageObject();
                this.audioToSendMessageObject.audioProgress = player.audioProgress;
                this.audioToSendMessageObject.audioProgressSec = player.audioProgressSec;
                if (!this.recordedAudioSeekBar.isDragging()) {
                    this.recordedAudioSeekBar.setProgress(this.audioToSendMessageObject.audioProgress);
                    return;
                }
                return;
            }
            return;
        }
        if (id == NotificationCenter.featuredStickersDidLoad) {
            if (this.emojiButton != null) {
                int a3 = 0;
                while (true) {
                    ImageView[] imageViewArr = this.emojiButton;
                    if (a3 < imageViewArr.length) {
                        imageViewArr[a3].invalidate();
                        a3++;
                    } else {
                        return;
                    }
                }
            }
        } else {
            if (id == NotificationCenter.messageReceivedByServer) {
                Boolean scheduled = (Boolean) args[6];
                if (scheduled.booleanValue()) {
                    return;
                }
                long did = ((Long) args[3]).longValue();
                if (did == this.dialog_id && (chatFull = this.info) != null && chatFull.slowmode_seconds != 0 && (chat = this.accountInstance.getMessagesController().getChat(Integer.valueOf(this.info.id))) != null && !ChatObject.hasAdminRights(chat)) {
                    this.info.slowmode_next_send_date = ConnectionsManager.getInstance(this.currentAccount).getCurrentTime() + this.info.slowmode_seconds;
                    this.info.flags |= 262144;
                    setSlowModeTimer(this.info.slowmode_next_send_date);
                    return;
                }
                return;
            }
            if (id == NotificationCenter.sendingMessagesChanged && this.info != null) {
                updateSlowModeText();
            }
        }
    }

    public void onRequestPermissionsResultFragment(int requestCode, String[] permissions, int[] grantResults) {
        if (requestCode == 2 && this.pendingLocationButton != null) {
            if (grantResults.length > 0 && grantResults[0] == 0) {
                SendMessagesHelper.getInstance(this.currentAccount).sendCurrentLocation(this.pendingMessageObject, this.pendingLocationButton);
            }
            this.pendingLocationButton = null;
            this.pendingMessageObject = null;
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void checkStickresExpandHeight() {
        int origHeight = AndroidUtilities.displaySize.x > AndroidUtilities.displaySize.y ? this.keyboardHeightLand : this.keyboardHeight;
        int newHeight = (((this.originalViewHeight - (Build.VERSION.SDK_INT >= 21 ? AndroidUtilities.statusBarHeight : 0)) - ActionBar.getCurrentActionBarHeight()) - getHeight()) + Theme.chat_composeShadowDrawable.getIntrinsicHeight();
        if (this.searchingType == 2) {
            newHeight = Math.min(newHeight, AndroidUtilities.dp(120.0f) + origHeight);
        }
        int currentHeight = this.emojiView.getLayoutParams().height;
        if (currentHeight == newHeight) {
            return;
        }
        Animator animator = this.stickersExpansionAnim;
        if (animator != null) {
            animator.cancel();
            this.stickersExpansionAnim = null;
        }
        this.stickersExpandedHeight = newHeight;
        if (currentHeight <= newHeight) {
            this.emojiView.getLayoutParams().height = this.stickersExpandedHeight;
            this.sizeNotifierLayout.requestLayout();
            int start = this.messageEditText.getSelectionStart();
            int end = this.messageEditText.getSelectionEnd();
            EditTextCaption editTextCaption = this.messageEditText;
            editTextCaption.setText(editTextCaption.getText());
            this.messageEditText.setSelection(start, end);
            AnimatorSet anims = new AnimatorSet();
            anims.playTogether(ObjectAnimator.ofInt(this, (Property<ChatActivityEnterView, Integer>) this.roundedTranslationYProperty, -(this.stickersExpandedHeight - origHeight)), ObjectAnimator.ofInt(this.emojiView, (Property<EmojiView, Integer>) this.roundedTranslationYProperty, -(this.stickersExpandedHeight - origHeight)));
            ((ObjectAnimator) anims.getChildAnimations().get(0)).addUpdateListener(new ValueAnimator.AnimatorUpdateListener() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$ChatActivityEnterView$imHlMGos4QhtDJm8ImZ_CiCKiHg
                @Override // android.animation.ValueAnimator.AnimatorUpdateListener
                public final void onAnimationUpdate(ValueAnimator valueAnimator) {
                    this.f$0.lambda$checkStickresExpandHeight$30$ChatActivityEnterView(valueAnimator);
                }
            });
            anims.setDuration(400L);
            anims.setInterpolator(CubicBezierInterpolator.EASE_OUT_QUINT);
            anims.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.components.ChatActivityEnterView.39
                @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                public void onAnimationEnd(Animator animation) {
                    ChatActivityEnterView.this.stickersExpansionAnim = null;
                    ChatActivityEnterView.this.emojiView.setLayerType(0, null);
                }
            });
            this.stickersExpansionAnim = anims;
            this.emojiView.setLayerType(2, null);
            anims.start();
            return;
        }
        AnimatorSet anims2 = new AnimatorSet();
        anims2.playTogether(ObjectAnimator.ofInt(this, (Property<ChatActivityEnterView, Integer>) this.roundedTranslationYProperty, -(this.stickersExpandedHeight - origHeight)), ObjectAnimator.ofInt(this.emojiView, (Property<EmojiView, Integer>) this.roundedTranslationYProperty, -(this.stickersExpandedHeight - origHeight)));
        ((ObjectAnimator) anims2.getChildAnimations().get(0)).addUpdateListener(new ValueAnimator.AnimatorUpdateListener() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$ChatActivityEnterView$rRv87cJwrrKf-EPaLsLaz51qVBA
            @Override // android.animation.ValueAnimator.AnimatorUpdateListener
            public final void onAnimationUpdate(ValueAnimator valueAnimator) {
                this.f$0.lambda$checkStickresExpandHeight$29$ChatActivityEnterView(valueAnimator);
            }
        });
        anims2.setDuration(400L);
        anims2.setInterpolator(CubicBezierInterpolator.EASE_OUT_QUINT);
        anims2.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.components.ChatActivityEnterView.38
            @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
            public void onAnimationEnd(Animator animation) {
                ChatActivityEnterView.this.stickersExpansionAnim = null;
                if (ChatActivityEnterView.this.emojiView != null) {
                    ChatActivityEnterView.this.emojiView.getLayoutParams().height = ChatActivityEnterView.this.stickersExpandedHeight;
                    ChatActivityEnterView.this.emojiView.setLayerType(0, null);
                }
            }
        });
        this.stickersExpansionAnim = anims2;
        this.emojiView.setLayerType(2, null);
        anims2.start();
    }

    public /* synthetic */ void lambda$checkStickresExpandHeight$29$ChatActivityEnterView(ValueAnimator animation) {
        this.sizeNotifierLayout.invalidate();
    }

    public /* synthetic */ void lambda$checkStickresExpandHeight$30$ChatActivityEnterView(ValueAnimator animation) {
        this.sizeNotifierLayout.invalidate();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void setStickersExpanded(boolean expanded, boolean animated, boolean byDrag) {
        if (this.emojiView != null) {
            if (!byDrag && this.stickersExpanded == expanded) {
                return;
            }
            this.stickersExpanded = expanded;
            ChatActivityEnterViewDelegate chatActivityEnterViewDelegate = this.delegate;
            if (chatActivityEnterViewDelegate != null) {
                chatActivityEnterViewDelegate.onStickersExpandedChange();
            }
            final int origHeight = AndroidUtilities.displaySize.x > AndroidUtilities.displaySize.y ? this.keyboardHeightLand : this.keyboardHeight;
            Animator animator = this.stickersExpansionAnim;
            if (animator != null) {
                animator.cancel();
                this.stickersExpansionAnim = null;
            }
            if (this.stickersExpanded) {
                NotificationCenter.getGlobalInstance().postNotificationName(NotificationCenter.stopAllHeavyOperations, 1);
                int height = this.sizeNotifierLayout.getHeight();
                this.originalViewHeight = height;
                int currentActionBarHeight = (((height - (Build.VERSION.SDK_INT >= 21 ? AndroidUtilities.statusBarHeight : 0)) - ActionBar.getCurrentActionBarHeight()) - getHeight()) + Theme.chat_composeShadowDrawable.getIntrinsicHeight();
                this.stickersExpandedHeight = currentActionBarHeight;
                if (this.searchingType == 2) {
                    this.stickersExpandedHeight = Math.min(currentActionBarHeight, AndroidUtilities.dp(120.0f) + origHeight);
                }
                this.emojiView.getLayoutParams().height = this.stickersExpandedHeight;
                this.sizeNotifierLayout.requestLayout();
                this.sizeNotifierLayout.setForeground(new ScrimDrawable());
                int start = this.messageEditText.getSelectionStart();
                int end = this.messageEditText.getSelectionEnd();
                EditTextCaption editTextCaption = this.messageEditText;
                editTextCaption.setText(editTextCaption.getText());
                this.messageEditText.setSelection(start, end);
                if (animated) {
                    AnimatorSet anims = new AnimatorSet();
                    anims.playTogether(ObjectAnimator.ofInt(this, (Property<ChatActivityEnterView, Integer>) this.roundedTranslationYProperty, -(this.stickersExpandedHeight - origHeight)), ObjectAnimator.ofInt(this.emojiView, (Property<EmojiView, Integer>) this.roundedTranslationYProperty, -(this.stickersExpandedHeight - origHeight)), ObjectAnimator.ofFloat(this.stickersArrow, "animationProgress", 1.0f));
                    anims.setDuration(400L);
                    anims.setInterpolator(CubicBezierInterpolator.EASE_OUT_QUINT);
                    ((ObjectAnimator) anims.getChildAnimations().get(0)).addUpdateListener(new ValueAnimator.AnimatorUpdateListener() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$ChatActivityEnterView$6KpPl3sVxCtdlHiCFmdXkVtQpIE
                        @Override // android.animation.ValueAnimator.AnimatorUpdateListener
                        public final void onAnimationUpdate(ValueAnimator valueAnimator) {
                            this.f$0.lambda$setStickersExpanded$31$ChatActivityEnterView(origHeight, valueAnimator);
                        }
                    });
                    anims.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.components.ChatActivityEnterView.40
                        @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                        public void onAnimationEnd(Animator animation) {
                            ChatActivityEnterView.this.stickersExpansionAnim = null;
                            ChatActivityEnterView.this.emojiView.setLayerType(0, null);
                            NotificationCenter.getGlobalInstance().postNotificationName(NotificationCenter.startAllHeavyOperations, 512);
                        }
                    });
                    this.stickersExpansionAnim = anims;
                    this.emojiView.setLayerType(2, null);
                    NotificationCenter.getGlobalInstance().postNotificationName(NotificationCenter.stopAllHeavyOperations, 512);
                    anims.start();
                } else {
                    this.stickersExpansionProgress = 1.0f;
                    setTranslationY(-(this.stickersExpandedHeight - origHeight));
                    this.emojiView.setTranslationY(-(this.stickersExpandedHeight - origHeight));
                    this.stickersArrow.setAnimationProgress(1.0f);
                }
            } else {
                NotificationCenter.getGlobalInstance().postNotificationName(NotificationCenter.startAllHeavyOperations, 1);
                if (animated) {
                    this.closeAnimationInProgress = true;
                    AnimatorSet anims2 = new AnimatorSet();
                    anims2.playTogether(ObjectAnimator.ofInt(this, (Property<ChatActivityEnterView, Integer>) this.roundedTranslationYProperty, 0), ObjectAnimator.ofInt(this.emojiView, (Property<EmojiView, Integer>) this.roundedTranslationYProperty, 0), ObjectAnimator.ofFloat(this.stickersArrow, "animationProgress", 0.0f));
                    anims2.setDuration(400L);
                    anims2.setInterpolator(CubicBezierInterpolator.EASE_OUT_QUINT);
                    ((ObjectAnimator) anims2.getChildAnimations().get(0)).addUpdateListener(new ValueAnimator.AnimatorUpdateListener() { // from class: im.uwrkaxlmjj.ui.components.-$$Lambda$ChatActivityEnterView$rMf_mUbF4bSgshxm5q9Hk5Je1JM
                        @Override // android.animation.ValueAnimator.AnimatorUpdateListener
                        public final void onAnimationUpdate(ValueAnimator valueAnimator) {
                            this.f$0.lambda$setStickersExpanded$32$ChatActivityEnterView(origHeight, valueAnimator);
                        }
                    });
                    anims2.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.components.ChatActivityEnterView.41
                        @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                        public void onAnimationEnd(Animator animation) {
                            ChatActivityEnterView.this.closeAnimationInProgress = false;
                            ChatActivityEnterView.this.stickersExpansionAnim = null;
                            if (ChatActivityEnterView.this.emojiView != null) {
                                ChatActivityEnterView.this.emojiView.getLayoutParams().height = origHeight;
                                ChatActivityEnterView.this.emojiView.setLayerType(0, null);
                            }
                            if (ChatActivityEnterView.this.sizeNotifierLayout != null) {
                                ChatActivityEnterView.this.sizeNotifierLayout.requestLayout();
                                ChatActivityEnterView.this.sizeNotifierLayout.setForeground(null);
                                ChatActivityEnterView.this.sizeNotifierLayout.setWillNotDraw(false);
                            }
                            NotificationCenter.getGlobalInstance().postNotificationName(NotificationCenter.startAllHeavyOperations, 512);
                        }
                    });
                    this.stickersExpansionAnim = anims2;
                    this.emojiView.setLayerType(2, null);
                    NotificationCenter.getGlobalInstance().postNotificationName(NotificationCenter.stopAllHeavyOperations, 512);
                    anims2.start();
                } else {
                    this.stickersExpansionProgress = 0.0f;
                    setTranslationY(0.0f);
                    this.emojiView.setTranslationY(0.0f);
                    this.emojiView.getLayoutParams().height = origHeight;
                    this.sizeNotifierLayout.requestLayout();
                    this.sizeNotifierLayout.setForeground(null);
                    this.sizeNotifierLayout.setWillNotDraw(false);
                    this.stickersArrow.setAnimationProgress(0.0f);
                }
            }
            if (expanded) {
                this.expandStickersButton.setContentDescription(LocaleController.getString("AccDescrCollapsePanel", R.string.AccDescrCollapsePanel));
            } else {
                this.expandStickersButton.setContentDescription(LocaleController.getString("AccDescrExpandPanel", R.string.AccDescrExpandPanel));
            }
        }
    }

    public /* synthetic */ void lambda$setStickersExpanded$31$ChatActivityEnterView(int origHeight, ValueAnimator animation) {
        this.stickersExpansionProgress = getTranslationY() / (-(this.stickersExpandedHeight - origHeight));
        this.sizeNotifierLayout.invalidate();
    }

    public /* synthetic */ void lambda$setStickersExpanded$32$ChatActivityEnterView(int origHeight, ValueAnimator animation) {
        this.stickersExpansionProgress = getTranslationY() / (-(this.stickersExpandedHeight - origHeight));
        this.sizeNotifierLayout.invalidate();
    }

    public void updateMenuViewStatus() {
        if (this.menuView != null && this.menuViewVisible && isPopupShowing()) {
            EnterMenuView enterMenuView = this.menuView;
            ChatActivity chatActivity = this.parentFragment;
            enterMenuView.setCurrentChat(chatActivity != null ? chatActivity.getCurrentChat() : null);
        }
    }

    private class ScrimDrawable extends Drawable {
        private Paint paint;

        public ScrimDrawable() {
            Paint paint = new Paint();
            this.paint = paint;
            paint.setColor(0);
        }

        @Override // android.graphics.drawable.Drawable
        public void draw(Canvas canvas) {
            if (ChatActivityEnterView.this.emojiView != null) {
                this.paint.setAlpha(Math.round(ChatActivityEnterView.this.stickersExpansionProgress * 102.0f));
                canvas.drawRect(0.0f, 0.0f, ChatActivityEnterView.this.getWidth(), (ChatActivityEnterView.this.emojiView.getY() - ChatActivityEnterView.this.getHeight()) + Theme.chat_composeShadowDrawable.getIntrinsicHeight(), this.paint);
            }
        }

        @Override // android.graphics.drawable.Drawable
        public void setAlpha(int alpha) {
        }

        @Override // android.graphics.drawable.Drawable
        public void setColorFilter(ColorFilter colorFilter) {
        }

        @Override // android.graphics.drawable.Drawable
        public int getOpacity() {
            return -2;
        }
    }
}
