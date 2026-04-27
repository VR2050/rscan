package im.uwrkaxlmjj.ui;

import android.animation.Animator;
import android.animation.AnimatorListenerAdapter;
import android.animation.AnimatorSet;
import android.animation.ArgbEvaluator;
import android.animation.ObjectAnimator;
import android.app.Activity;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.SharedPreferences;
import android.graphics.Bitmap;
import android.graphics.Canvas;
import android.graphics.ColorFilter;
import android.graphics.Matrix;
import android.graphics.Paint;
import android.graphics.Rect;
import android.graphics.RectF;
import android.graphics.Typeface;
import android.graphics.drawable.ColorDrawable;
import android.graphics.drawable.Drawable;
import android.graphics.drawable.GradientDrawable;
import android.media.AudioManager;
import android.os.Build;
import android.os.Bundle;
import android.text.Editable;
import android.text.SpannableString;
import android.text.SpannableStringBuilder;
import android.text.TextPaint;
import android.text.TextUtils;
import android.text.TextWatcher;
import android.text.style.CharacterStyle;
import android.text.style.ForegroundColorSpan;
import android.view.KeyEvent;
import android.view.View;
import android.view.WindowManager;
import android.view.accessibility.AccessibilityManager;
import android.view.animation.DecelerateInterpolator;
import android.view.inputmethod.InputMethodManager;
import android.widget.EditText;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import androidx.core.view.ViewCompat;
import androidx.palette.graphics.Palette;
import com.google.android.exoplayer2.DefaultRenderersFactory;
import com.google.android.exoplayer2.text.ttml.TtmlNode;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.ApplicationLoader;
import im.uwrkaxlmjj.messenger.BuildVars;
import im.uwrkaxlmjj.messenger.ContactsController;
import im.uwrkaxlmjj.messenger.Emoji;
import im.uwrkaxlmjj.messenger.FileLog;
import im.uwrkaxlmjj.messenger.ImageLocation;
import im.uwrkaxlmjj.messenger.ImageReceiver;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.messenger.MessagesController;
import im.uwrkaxlmjj.messenger.NotificationCenter;
import im.uwrkaxlmjj.messenger.SendMessagesHelper;
import im.uwrkaxlmjj.messenger.UserConfig;
import im.uwrkaxlmjj.messenger.Utilities;
import im.uwrkaxlmjj.messenger.voip.EncryptionKeyEmojifier;
import im.uwrkaxlmjj.messenger.voip.VoIPBaseService;
import im.uwrkaxlmjj.messenger.voip.VoIPController;
import im.uwrkaxlmjj.messenger.voip.VoIPService;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.ui.actionbar.AlertDialog;
import im.uwrkaxlmjj.ui.actionbar.BottomSheet;
import im.uwrkaxlmjj.ui.actionbar.DarkAlertDialog;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.components.BackupImageView;
import im.uwrkaxlmjj.ui.components.CorrectlyMeasuringTextView;
import im.uwrkaxlmjj.ui.components.CubicBezierInterpolator;
import im.uwrkaxlmjj.ui.components.IdenticonDrawable;
import im.uwrkaxlmjj.ui.components.LayoutHelper;
import im.uwrkaxlmjj.ui.components.voip.CallSwipeView;
import im.uwrkaxlmjj.ui.components.voip.CheckableImageView;
import im.uwrkaxlmjj.ui.components.voip.DarkTheme;
import im.uwrkaxlmjj.ui.components.voip.FabBackgroundDrawable;
import im.uwrkaxlmjj.ui.components.voip.VoIPHelper;
import java.io.ByteArrayOutputStream;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class VoIPActivity extends Activity implements VoIPBaseService.StateListener, NotificationCenter.NotificationCenterDelegate {
    private static final String TAG = "hchat-voip-ui";
    private View acceptBtn;
    private CallSwipeView acceptSwipe;
    private TextView accountNameText;
    private ImageView addMemberBtn;
    private ImageView blurOverlayView1;
    private ImageView blurOverlayView2;
    private Bitmap blurredPhoto1;
    private Bitmap blurredPhoto2;
    private LinearLayout bottomButtons;
    private TextView brandingText;
    private int callState;
    private View cancelBtn;
    private ImageView chatBtn;
    private FrameLayout content;
    private Animator currentAcceptAnim;
    private Animator currentDeclineAnim;
    private View declineBtn;
    private CallSwipeView declineSwipe;
    private TextView durationText;
    private AnimatorSet ellAnimator;
    private TextAlphaSpan[] ellSpans;
    private AnimatorSet emojiAnimator;
    boolean emojiExpanded;
    private TextView emojiExpandedText;
    boolean emojiTooltipVisible;
    private LinearLayout emojiWrap;
    private View endBtn;
    private FabBackgroundDrawable endBtnBg;
    private View endBtnIcon;
    private TextView hintTextView;
    private boolean isIncomingWaiting;
    private boolean keyEmojiVisible;
    private String lastStateText;
    private CheckableImageView micToggle;
    private TextView nameText;
    private BackupImageView photoView;
    private AnimatorSet retryAnim;
    private boolean retrying;
    private int signalBarsCount;
    private SignalBarsDrawable signalBarsDrawable;
    private CheckableImageView spkToggle;
    private TextView stateText;
    private TextView stateText2;
    private LinearLayout swipeViewsWrap;
    private Animator textChangingAnim;
    private Animator tooltipAnim;
    private Runnable tooltipHider;
    private TLRPC.User user;
    private int currentAccount = -1;
    private boolean firstStateChange = true;
    private boolean didAcceptFromHere = false;
    private ImageView[] keyEmojiViews = new ImageView[4];

    @Override // android.app.Activity
    protected void onCreate(Bundle savedInstanceState) {
        requestWindowFeature(1);
        getWindow().addFlags(524288);
        super.onCreate(savedInstanceState);
        if (VoIPService.getSharedInstance() == null) {
            finish();
            return;
        }
        int account = VoIPService.getSharedInstance().getAccount();
        this.currentAccount = account;
        if (account == -1) {
            finish();
            return;
        }
        if ((getResources().getConfiguration().screenLayout & 15) < 3) {
            setRequestedOrientation(1);
        }
        View contentView = createContentView();
        setContentView(contentView);
        if (Build.VERSION.SDK_INT >= 21) {
            getWindow().addFlags(Integer.MIN_VALUE);
            getWindow().setStatusBarColor(0);
            getWindow().setNavigationBarColor(0);
            getWindow().getDecorView().setSystemUiVisibility(1792);
        } else if (Build.VERSION.SDK_INT >= 19) {
            getWindow().addFlags(201326592);
            getWindow().getDecorView().setSystemUiVisibility(1792);
        }
        TLRPC.User user = VoIPService.getSharedInstance().getUser();
        this.user = user;
        if (user.photo != null) {
            this.photoView.getImageReceiver().setDelegate(new ImageReceiver.ImageReceiverDelegate() { // from class: im.uwrkaxlmjj.ui.VoIPActivity.1
                @Override // im.uwrkaxlmjj.messenger.ImageReceiver.ImageReceiverDelegate
                public /* synthetic */ void onAnimationReady(ImageReceiver imageReceiver) {
                    ImageReceiver.ImageReceiverDelegate.CC.$default$onAnimationReady(this, imageReceiver);
                }

                @Override // im.uwrkaxlmjj.messenger.ImageReceiver.ImageReceiverDelegate
                public void didSetImage(ImageReceiver imageReceiver, boolean set, boolean thumb) {
                    ImageReceiver.BitmapHolder bmp = imageReceiver.getBitmapSafe();
                    if (bmp != null) {
                        VoIPActivity.this.updateBlurredPhotos(bmp);
                    }
                }
            });
            this.photoView.setImage(ImageLocation.getForUser(this.user, true), (String) null, new ColorDrawable(-16777216), this.user);
            this.photoView.setLayerType(2, null);
        } else {
            this.photoView.setVisibility(8);
            contentView.setBackgroundDrawable(new GradientDrawable(GradientDrawable.Orientation.TOP_BOTTOM, new int[]{-14994098, -14328963}));
        }
        getWindow().setBackgroundDrawable(new ColorDrawable(0));
        setVolumeControlStream(0);
        this.nameText.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.VoIPActivity.2
            private int tapCount = 0;

            @Override // android.view.View.OnClickListener
            public void onClick(View v) {
                int i;
                if (BuildVars.VOIP_DEBUG || (i = this.tapCount) == 9) {
                    VoIPActivity.this.showDebugAlert();
                    this.tapCount = 0;
                } else {
                    this.tapCount = i + 1;
                }
            }
        });
        this.endBtn.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.VoIPActivity.3
            @Override // android.view.View.OnClickListener
            public void onClick(View v) {
                VoIPActivity.this.endBtn.setEnabled(false);
                if (VoIPActivity.this.retrying) {
                    Intent intent = new Intent(VoIPActivity.this, (Class<?>) VoIPService.class);
                    intent.putExtra("user_id", VoIPActivity.this.user.id);
                    intent.putExtra("is_outgoing", true);
                    intent.putExtra("start_incall_activity", false);
                    intent.putExtra("account", VoIPActivity.this.currentAccount);
                    try {
                        VoIPActivity.this.startService(intent);
                    } catch (Throwable e) {
                        FileLog.e(e);
                    }
                    VoIPActivity.this.hideRetry();
                    VoIPActivity.this.endBtn.postDelayed(new Runnable() { // from class: im.uwrkaxlmjj.ui.VoIPActivity.3.1
                        @Override // java.lang.Runnable
                        public void run() {
                            if (VoIPService.getSharedInstance() == null && !VoIPActivity.this.isFinishing()) {
                                VoIPActivity.this.endBtn.postDelayed(this, 100L);
                            } else if (VoIPService.getSharedInstance() != null) {
                                VoIPService.getSharedInstance().registerStateListener(VoIPActivity.this);
                            }
                        }
                    }, 100L);
                    return;
                }
                if (VoIPService.getSharedInstance() != null) {
                    VoIPService.getSharedInstance().hangUp();
                }
            }
        });
        this.spkToggle.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$VoIPActivity$XXuYDv1Ar4gDutQFnp6NGIyj27g
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                this.f$0.lambda$onCreate$0$VoIPActivity(view);
            }
        });
        this.micToggle.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$VoIPActivity$EJ5FNbmWVI8JeJLzX_JhjV1bCZM
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                this.f$0.lambda$onCreate$1$VoIPActivity(view);
            }
        });
        this.chatBtn.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$VoIPActivity$CSDHXeZFEEVKWee8HhPW4Nl-Ok8
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                this.f$0.lambda$onCreate$2$VoIPActivity(view);
            }
        });
        this.spkToggle.setChecked(((AudioManager) getSystemService("audio")).isSpeakerphoneOn());
        this.micToggle.setChecked(VoIPService.getSharedInstance().isMicMute());
        onAudioSettingsChanged();
        this.nameText.setText(ContactsController.formatName(this.user.first_name, this.user.last_name));
        VoIPService.getSharedInstance().registerStateListener(this);
        this.acceptSwipe.setListener(new CallSwipeView.Listener() { // from class: im.uwrkaxlmjj.ui.VoIPActivity.4
            @Override // im.uwrkaxlmjj.ui.components.voip.CallSwipeView.Listener
            public void onDragComplete() {
                VoIPActivity.this.acceptSwipe.setEnabled(false);
                VoIPActivity.this.declineSwipe.setEnabled(false);
                if (VoIPService.getSharedInstance() != null) {
                    VoIPActivity.this.didAcceptFromHere = true;
                    if (Build.VERSION.SDK_INT >= 23 && VoIPActivity.this.checkSelfPermission("android.permission.RECORD_AUDIO") != 0) {
                        VoIPActivity.this.requestPermissions(new String[]{"android.permission.RECORD_AUDIO"}, 101);
                        return;
                    } else {
                        VoIPService.getSharedInstance().acceptIncomingCall();
                        VoIPActivity.this.callAccepted();
                        return;
                    }
                }
                VoIPActivity.this.finish();
            }

            @Override // im.uwrkaxlmjj.ui.components.voip.CallSwipeView.Listener
            public void onDragStart() {
                if (VoIPActivity.this.currentDeclineAnim != null) {
                    VoIPActivity.this.currentDeclineAnim.cancel();
                }
                AnimatorSet set = new AnimatorSet();
                set.playTogether(ObjectAnimator.ofFloat(VoIPActivity.this.declineSwipe, "alpha", 0.2f), ObjectAnimator.ofFloat(VoIPActivity.this.declineBtn, "alpha", 0.2f));
                set.setDuration(200L);
                set.setInterpolator(CubicBezierInterpolator.DEFAULT);
                set.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.VoIPActivity.4.1
                    @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                    public void onAnimationEnd(Animator animation) {
                        VoIPActivity.this.currentDeclineAnim = null;
                    }
                });
                VoIPActivity.this.currentDeclineAnim = set;
                set.start();
                VoIPActivity.this.declineSwipe.stopAnimatingArrows();
            }

            @Override // im.uwrkaxlmjj.ui.components.voip.CallSwipeView.Listener
            public void onDragCancel() {
                if (VoIPActivity.this.currentDeclineAnim != null) {
                    VoIPActivity.this.currentDeclineAnim.cancel();
                }
                AnimatorSet set = new AnimatorSet();
                set.playTogether(ObjectAnimator.ofFloat(VoIPActivity.this.declineSwipe, "alpha", 1.0f), ObjectAnimator.ofFloat(VoIPActivity.this.declineBtn, "alpha", 1.0f));
                set.setDuration(200L);
                set.setInterpolator(CubicBezierInterpolator.DEFAULT);
                set.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.VoIPActivity.4.2
                    @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                    public void onAnimationEnd(Animator animation) {
                        VoIPActivity.this.currentDeclineAnim = null;
                    }
                });
                VoIPActivity.this.currentDeclineAnim = set;
                set.start();
                VoIPActivity.this.declineSwipe.startAnimatingArrows();
            }
        });
        this.declineSwipe.setListener(new CallSwipeView.Listener() { // from class: im.uwrkaxlmjj.ui.VoIPActivity.5
            @Override // im.uwrkaxlmjj.ui.components.voip.CallSwipeView.Listener
            public void onDragComplete() {
                VoIPActivity.this.acceptSwipe.setEnabled(false);
                VoIPActivity.this.declineSwipe.setEnabled(false);
                if (VoIPService.getSharedInstance() != null) {
                    VoIPService.getSharedInstance().declineIncomingCall(4, null);
                } else {
                    VoIPActivity.this.finish();
                }
            }

            @Override // im.uwrkaxlmjj.ui.components.voip.CallSwipeView.Listener
            public void onDragStart() {
                if (VoIPActivity.this.currentAcceptAnim != null) {
                    VoIPActivity.this.currentAcceptAnim.cancel();
                }
                AnimatorSet set = new AnimatorSet();
                set.playTogether(ObjectAnimator.ofFloat(VoIPActivity.this.acceptSwipe, "alpha", 0.2f), ObjectAnimator.ofFloat(VoIPActivity.this.acceptBtn, "alpha", 0.2f));
                set.setDuration(200L);
                set.setInterpolator(new DecelerateInterpolator());
                set.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.VoIPActivity.5.1
                    @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                    public void onAnimationEnd(Animator animation) {
                        VoIPActivity.this.currentAcceptAnim = null;
                    }
                });
                VoIPActivity.this.currentAcceptAnim = set;
                set.start();
                VoIPActivity.this.acceptSwipe.stopAnimatingArrows();
            }

            @Override // im.uwrkaxlmjj.ui.components.voip.CallSwipeView.Listener
            public void onDragCancel() {
                if (VoIPActivity.this.currentAcceptAnim != null) {
                    VoIPActivity.this.currentAcceptAnim.cancel();
                }
                AnimatorSet set = new AnimatorSet();
                set.playTogether(ObjectAnimator.ofFloat(VoIPActivity.this.acceptSwipe, "alpha", 1.0f), ObjectAnimator.ofFloat(VoIPActivity.this.acceptBtn, "alpha", 1.0f));
                set.setDuration(200L);
                set.setInterpolator(CubicBezierInterpolator.DEFAULT);
                set.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.VoIPActivity.5.2
                    @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                    public void onAnimationEnd(Animator animation) {
                        VoIPActivity.this.currentAcceptAnim = null;
                    }
                });
                VoIPActivity.this.currentAcceptAnim = set;
                set.start();
                VoIPActivity.this.acceptSwipe.startAnimatingArrows();
            }
        });
        this.cancelBtn.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.VoIPActivity.6
            @Override // android.view.View.OnClickListener
            public void onClick(View v) {
                VoIPActivity.this.finish();
            }
        });
        getWindow().getDecorView().setKeepScreenOn(true);
        NotificationCenter.getGlobalInstance().addObserver(this, NotificationCenter.emojiDidLoad);
        NotificationCenter.getGlobalInstance().addObserver(this, NotificationCenter.closeInCallActivity);
        this.hintTextView.setText(LocaleController.formatString("CallEmojiKeyTooltip", R.string.CallEmojiKeyTooltip, this.user.first_name));
        this.emojiExpandedText.setText(LocaleController.formatString("CallEmojiKeyTooltip", R.string.CallEmojiKeyTooltip, this.user.first_name));
        AccessibilityManager am = (AccessibilityManager) getSystemService("accessibility");
        if (am.isTouchExplorationEnabled()) {
            this.nameText.postDelayed(new Runnable() { // from class: im.uwrkaxlmjj.ui.VoIPActivity.7
                @Override // java.lang.Runnable
                public void run() {
                    VoIPActivity.this.nameText.sendAccessibilityEvent(8);
                }
            }, 500L);
        }
    }

    public /* synthetic */ void lambda$onCreate$0$VoIPActivity(View v) {
        VoIPService svc = VoIPService.getSharedInstance();
        if (svc == null) {
            return;
        }
        svc.toggleSpeakerphoneOrShowRouteSheet(this);
    }

    public /* synthetic */ void lambda$onCreate$1$VoIPActivity(View v) {
        if (VoIPService.getSharedInstance() == null) {
            finish();
            return;
        }
        boolean checked = !this.micToggle.isChecked();
        this.micToggle.setChecked(checked);
        VoIPService.getSharedInstance().setMicMute(checked);
    }

    public /* synthetic */ void lambda$onCreate$2$VoIPActivity(View v) {
        if (this.isIncomingWaiting) {
            showMessagesSheet();
            return;
        }
        Intent intent = new Intent(ApplicationLoader.applicationContext, (Class<?>) LaunchActivity.class);
        intent.setAction("com.tmessages.openchat" + Math.random() + Integer.MAX_VALUE);
        intent.putExtra("currentAccount", this.currentAccount);
        intent.setFlags(32768);
        intent.putExtra("userId", this.user.id);
        startActivity(intent);
        finish();
    }

    private View createContentView() {
        FrameLayout frameLayout = new FrameLayout(this) { // from class: im.uwrkaxlmjj.ui.VoIPActivity.8
            private void setNegativeMargins(Rect insets, FrameLayout.LayoutParams lp) {
                lp.topMargin = -insets.top;
                lp.bottomMargin = -insets.bottom;
                lp.leftMargin = -insets.left;
                lp.rightMargin = -insets.right;
            }

            @Override // android.view.View
            protected boolean fitSystemWindows(Rect insets) {
                setNegativeMargins(insets, (FrameLayout.LayoutParams) VoIPActivity.this.photoView.getLayoutParams());
                setNegativeMargins(insets, (FrameLayout.LayoutParams) VoIPActivity.this.blurOverlayView1.getLayoutParams());
                setNegativeMargins(insets, (FrameLayout.LayoutParams) VoIPActivity.this.blurOverlayView2.getLayoutParams());
                return super.fitSystemWindows(insets);
            }
        };
        frameLayout.setBackgroundColor(0);
        frameLayout.setFitsSystemWindows(true);
        frameLayout.setClipToPadding(false);
        BackupImageView photo = new BackupImageView(this) { // from class: im.uwrkaxlmjj.ui.VoIPActivity.9
            private Drawable topGradient = getResources().getDrawable(R.drawable.gradient_top);
            private Drawable bottomGradient = getResources().getDrawable(R.drawable.gradient_bottom);
            private Paint paint = new Paint();

            @Override // im.uwrkaxlmjj.ui.components.BackupImageView, android.view.View
            protected void onDraw(Canvas canvas) {
                super.onDraw(canvas);
                this.paint.setColor(1275068416);
                canvas.drawRect(0.0f, 0.0f, getWidth(), getHeight(), this.paint);
                this.topGradient.setBounds(0, 0, getWidth(), AndroidUtilities.dp(170.0f));
                this.topGradient.setAlpha(128);
                this.topGradient.draw(canvas);
                this.bottomGradient.setBounds(0, getHeight() - AndroidUtilities.dp(220.0f), getWidth(), getHeight());
                this.bottomGradient.setAlpha(178);
                this.bottomGradient.draw(canvas);
            }
        };
        this.photoView = photo;
        frameLayout.addView(photo);
        ImageView imageView = new ImageView(this);
        this.blurOverlayView1 = imageView;
        imageView.setScaleType(ImageView.ScaleType.CENTER_CROP);
        this.blurOverlayView1.setAlpha(0.0f);
        frameLayout.addView(this.blurOverlayView1);
        ImageView imageView2 = new ImageView(this);
        this.blurOverlayView2 = imageView2;
        imageView2.setScaleType(ImageView.ScaleType.CENTER_CROP);
        this.blurOverlayView2.setAlpha(0.0f);
        frameLayout.addView(this.blurOverlayView2);
        TextView branding = new TextView(this);
        branding.setTextColor(-855638017);
        branding.setText(LocaleController.getString("VoipInCallBranding", R.string.VoipInCallBranding));
        Drawable logo = getResources().getDrawable(R.id.ic_launcher).mutate();
        logo.setAlpha(204);
        logo.setBounds(0, 0, AndroidUtilities.dp(15.0f), AndroidUtilities.dp(15.0f));
        SignalBarsDrawable signalBarsDrawable = new SignalBarsDrawable();
        this.signalBarsDrawable = signalBarsDrawable;
        signalBarsDrawable.setBounds(0, 0, signalBarsDrawable.getIntrinsicWidth(), this.signalBarsDrawable.getIntrinsicHeight());
        branding.setCompoundDrawables(LocaleController.isRTL ? this.signalBarsDrawable : logo, null, LocaleController.isRTL ? logo : this.signalBarsDrawable, null);
        branding.setTypeface(AndroidUtilities.getTypeface("fonts/rmedium.ttf"));
        branding.setGravity(LocaleController.isRTL ? 5 : 3);
        branding.setCompoundDrawablePadding(AndroidUtilities.dp(5.0f));
        branding.setTextSize(1, 14.0f);
        frameLayout.addView(branding, LayoutHelper.createFrame(-2.0f, -2.0f, (LocaleController.isRTL ? 5 : 3) | 48, 18.0f, 18.0f, 18.0f, 0.0f));
        this.brandingText = branding;
        TextView name = new TextView(this);
        name.setSingleLine();
        name.setTextColor(-1);
        name.setTextSize(1, 40.0f);
        name.setEllipsize(TextUtils.TruncateAt.END);
        name.setGravity(LocaleController.isRTL ? 5 : 3);
        name.setShadowLayer(AndroidUtilities.dp(3.0f), 0.0f, AndroidUtilities.dp(0.6666667f), 1275068416);
        name.setTypeface(Typeface.create("sans-serif-light", 0));
        this.nameText = name;
        frameLayout.addView(name, LayoutHelper.createFrame(-1.0f, -2.0f, 51, 16.0f, 43.0f, 18.0f, 0.0f));
        TextView state = new TextView(this);
        state.setTextColor(-855638017);
        state.setSingleLine();
        state.setEllipsize(TextUtils.TruncateAt.END);
        state.setTypeface(AndroidUtilities.getTypeface("fonts/rmedium.ttf"));
        state.setShadowLayer(AndroidUtilities.dp(3.0f), 0.0f, AndroidUtilities.dp(0.6666667f), 1275068416);
        state.setTextSize(1, 15.0f);
        state.setGravity(LocaleController.isRTL ? 5 : 3);
        this.stateText = state;
        frameLayout.addView(state, LayoutHelper.createFrame(-1.0f, -2.0f, 51, 18.0f, 98.0f, 18.0f, 0.0f));
        this.durationText = state;
        TextView state2 = new TextView(this);
        state2.setTextColor(-855638017);
        state2.setSingleLine();
        state2.setEllipsize(TextUtils.TruncateAt.END);
        state2.setTypeface(AndroidUtilities.getTypeface("fonts/rmedium.ttf"));
        state2.setShadowLayer(AndroidUtilities.dp(3.0f), 0.0f, AndroidUtilities.dp(0.6666667f), 1275068416);
        state2.setTextSize(1, 15.0f);
        state2.setGravity(LocaleController.isRTL ? 5 : 3);
        state2.setVisibility(8);
        this.stateText2 = state2;
        frameLayout.addView(state2, LayoutHelper.createFrame(-1.0f, -2.0f, 51, 18.0f, 98.0f, 18.0f, 0.0f));
        this.ellSpans = new TextAlphaSpan[]{new TextAlphaSpan(), new TextAlphaSpan(), new TextAlphaSpan()};
        LinearLayout buttons = new LinearLayout(this);
        buttons.setOrientation(0);
        frameLayout.addView(buttons, LayoutHelper.createFrame(-1, -2, 80));
        TextView accountName = new TextView(this);
        accountName.setTextColor(-855638017);
        accountName.setSingleLine();
        accountName.setEllipsize(TextUtils.TruncateAt.END);
        accountName.setShadowLayer(AndroidUtilities.dp(3.0f), 0.0f, AndroidUtilities.dp(0.6666667f), 1275068416);
        accountName.setTextSize(1, 15.0f);
        accountName.setGravity(LocaleController.isRTL ? 5 : 3);
        this.accountNameText = accountName;
        frameLayout.addView(accountName, LayoutHelper.createFrame(-1.0f, -2.0f, 51, 18.0f, 120.0f, 18.0f, 0.0f));
        CheckableImageView mic = new CheckableImageView(this);
        mic.setBackgroundResource(R.drawable.bg_voip_icon_btn);
        Drawable micIcon = getResources().getDrawable(R.drawable.ic_mic_off_white_24dp).mutate();
        mic.setAlpha(204);
        mic.setImageDrawable(micIcon);
        mic.setScaleType(ImageView.ScaleType.CENTER);
        mic.setContentDescription(LocaleController.getString("AccDescrMuteMic", R.string.AccDescrMuteMic));
        FrameLayout wrap = new FrameLayout(this);
        this.micToggle = mic;
        wrap.addView(mic, LayoutHelper.createFrame(38.0f, 38.0f, 81, 0.0f, 0.0f, 0.0f, 10.0f));
        buttons.addView(wrap, LayoutHelper.createLinear(0, -2, 1.0f));
        ImageView chat = new ImageView(this);
        Drawable chatIcon = getResources().getDrawable(R.drawable.ic_chat_bubble_white_24dp).mutate();
        chatIcon.setAlpha(204);
        chat.setImageDrawable(chatIcon);
        chat.setScaleType(ImageView.ScaleType.CENTER);
        chat.setContentDescription(LocaleController.getString("AccDescrOpenChat", R.string.AccDescrOpenChat));
        FrameLayout wrap2 = new FrameLayout(this);
        this.chatBtn = chat;
        wrap2.addView(chat, LayoutHelper.createFrame(38.0f, 38.0f, 81, 0.0f, 0.0f, 0.0f, 10.0f));
        buttons.addView(wrap2, LayoutHelper.createLinear(0, -2, 1.0f));
        CheckableImageView speaker = new CheckableImageView(this);
        speaker.setBackgroundResource(R.drawable.bg_voip_icon_btn);
        Drawable speakerIcon = getResources().getDrawable(R.drawable.ic_volume_up_white_24dp).mutate();
        speaker.setAlpha(204);
        speaker.setImageDrawable(speakerIcon);
        speaker.setScaleType(ImageView.ScaleType.CENTER);
        speaker.setContentDescription(LocaleController.getString("VoipAudioRoutingSpeaker", R.string.VoipAudioRoutingSpeaker));
        FrameLayout wrap3 = new FrameLayout(this);
        this.spkToggle = speaker;
        wrap3.addView(speaker, LayoutHelper.createFrame(38.0f, 38.0f, 81, 0.0f, 0.0f, 0.0f, 10.0f));
        buttons.addView(wrap3, LayoutHelper.createLinear(0, -2, 1.0f));
        this.bottomButtons = buttons;
        LinearLayout linearLayout = new LinearLayout(this);
        linearLayout.setOrientation(0);
        CallSwipeView callSwipeView = new CallSwipeView(this);
        callSwipeView.setColor(-12207027);
        callSwipeView.setContentDescription(LocaleController.getString("Accept", R.string.Accept));
        this.acceptSwipe = callSwipeView;
        linearLayout.addView(callSwipeView, LayoutHelper.createLinear(-1, 70, 1.0f, 4, 4, -35, 4));
        CallSwipeView callSwipeView2 = new CallSwipeView(this);
        callSwipeView2.setColor(-1696188);
        callSwipeView2.setContentDescription(LocaleController.getString("Decline", R.string.Decline));
        this.declineSwipe = callSwipeView2;
        linearLayout.addView(callSwipeView2, LayoutHelper.createLinear(-1, 70, 1.0f, -35, 4, 4, 4));
        this.swipeViewsWrap = linearLayout;
        frameLayout.addView(linearLayout, LayoutHelper.createFrame(-1.0f, -2.0f, 80, 20.0f, 0.0f, 20.0f, 68.0f));
        ImageView acceptBtn = new ImageView(this);
        FabBackgroundDrawable acceptBtnBg = new FabBackgroundDrawable();
        acceptBtnBg.setColor(-12207027);
        acceptBtn.setBackgroundDrawable(acceptBtnBg);
        acceptBtn.setImageResource(R.drawable.ic_call_end_white_36dp);
        acceptBtn.setScaleType(ImageView.ScaleType.MATRIX);
        Matrix matrix = new Matrix();
        matrix.setTranslate(AndroidUtilities.dp(17.0f), AndroidUtilities.dp(17.0f));
        matrix.postRotate(-135.0f, AndroidUtilities.dp(35.0f), AndroidUtilities.dp(35.0f));
        acceptBtn.setImageMatrix(matrix);
        this.acceptBtn = acceptBtn;
        frameLayout.addView(acceptBtn, LayoutHelper.createFrame(78.0f, 78.0f, 83, 20.0f, 0.0f, 0.0f, 68.0f));
        ImageView declineBtn = new ImageView(this);
        FabBackgroundDrawable rejectBtnBg = new FabBackgroundDrawable();
        rejectBtnBg.setColor(-1696188);
        declineBtn.setBackgroundDrawable(rejectBtnBg);
        declineBtn.setImageResource(R.drawable.ic_call_end_white_36dp);
        declineBtn.setScaleType(ImageView.ScaleType.CENTER);
        this.declineBtn = declineBtn;
        frameLayout.addView(declineBtn, LayoutHelper.createFrame(78.0f, 78.0f, 85, 0.0f, 0.0f, 20.0f, 68.0f));
        callSwipeView.setViewToDrag(acceptBtn, false);
        callSwipeView2.setViewToDrag(declineBtn, true);
        FrameLayout end = new FrameLayout(this);
        FabBackgroundDrawable endBtnBg = new FabBackgroundDrawable();
        endBtnBg.setColor(-1696188);
        this.endBtnBg = endBtnBg;
        end.setBackgroundDrawable(endBtnBg);
        ImageView endInner = new ImageView(this);
        endInner.setImageResource(R.drawable.ic_call_end_white_36dp);
        endInner.setScaleType(ImageView.ScaleType.CENTER);
        this.endBtnIcon = endInner;
        end.addView(endInner, LayoutHelper.createFrame(70, 70.0f));
        end.setForeground(getResources().getDrawable(R.drawable.fab_highlight_dark));
        end.setContentDescription(LocaleController.getString("VoipEndCall", R.string.VoipEndCall));
        this.endBtn = end;
        frameLayout.addView(end, LayoutHelper.createFrame(78.0f, 78.0f, 81, 0.0f, 0.0f, 0.0f, 68.0f));
        ImageView cancelBtn = new ImageView(this);
        FabBackgroundDrawable cancelBtnBg = new FabBackgroundDrawable();
        cancelBtnBg.setColor(-1);
        cancelBtn.setBackgroundDrawable(cancelBtnBg);
        cancelBtn.setImageResource(R.drawable.edit_cancel);
        cancelBtn.setColorFilter(-1996488704);
        cancelBtn.setScaleType(ImageView.ScaleType.CENTER);
        cancelBtn.setVisibility(8);
        cancelBtn.setContentDescription(LocaleController.getString("Cancel", R.string.Cancel));
        this.cancelBtn = cancelBtn;
        frameLayout.addView(cancelBtn, LayoutHelper.createFrame(78.0f, 78.0f, 83, 52.0f, 0.0f, 0.0f, 68.0f));
        LinearLayout linearLayout2 = new LinearLayout(this);
        this.emojiWrap = linearLayout2;
        linearLayout2.setOrientation(0);
        this.emojiWrap.setClipToPadding(false);
        this.emojiWrap.setPivotX(0.0f);
        this.emojiWrap.setPivotY(0.0f);
        this.emojiWrap.setPadding(AndroidUtilities.dp(14.0f), AndroidUtilities.dp(10.0f), AndroidUtilities.dp(14.0f), AndroidUtilities.dp(10.0f));
        int i = 0;
        while (i < 4) {
            ImageView emoji = new ImageView(this);
            emoji.setScaleType(ImageView.ScaleType.FIT_XY);
            this.emojiWrap.addView(emoji, LayoutHelper.createLinear(22, 22, i == 0 ? 0.0f : 4.0f, 0.0f, 0.0f, 0.0f));
            this.keyEmojiViews[i] = emoji;
            i++;
        }
        this.emojiWrap.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.VoIPActivity.10
            @Override // android.view.View.OnClickListener
            public void onClick(View v) {
                if (VoIPActivity.this.emojiTooltipVisible) {
                    VoIPActivity.this.setEmojiTooltipVisible(false);
                    if (VoIPActivity.this.tooltipHider != null) {
                        VoIPActivity.this.hintTextView.removeCallbacks(VoIPActivity.this.tooltipHider);
                        VoIPActivity.this.tooltipHider = null;
                    }
                }
                VoIPActivity.this.setEmojiExpanded(!r0.emojiExpanded);
            }
        });
        frameLayout.addView(this.emojiWrap, LayoutHelper.createFrame(-2, -2, (LocaleController.isRTL ? 3 : 5) | 48));
        this.emojiWrap.setOnLongClickListener(new View.OnLongClickListener() { // from class: im.uwrkaxlmjj.ui.VoIPActivity.11
            @Override // android.view.View.OnLongClickListener
            public boolean onLongClick(View v) {
                if (!VoIPActivity.this.emojiExpanded) {
                    if (VoIPActivity.this.tooltipHider != null) {
                        VoIPActivity.this.hintTextView.removeCallbacks(VoIPActivity.this.tooltipHider);
                        VoIPActivity.this.tooltipHider = null;
                    }
                    VoIPActivity.this.setEmojiTooltipVisible(!r0.emojiTooltipVisible);
                    if (VoIPActivity.this.emojiTooltipVisible) {
                        VoIPActivity.this.hintTextView.postDelayed(VoIPActivity.this.tooltipHider = new Runnable() { // from class: im.uwrkaxlmjj.ui.VoIPActivity.11.1
                            @Override // java.lang.Runnable
                            public void run() {
                                VoIPActivity.this.tooltipHider = null;
                                VoIPActivity.this.setEmojiTooltipVisible(false);
                            }
                        }, DefaultRenderersFactory.DEFAULT_ALLOWED_VIDEO_JOINING_TIME_MS);
                    }
                    return true;
                }
                return false;
            }
        });
        TextView textView = new TextView(this);
        this.emojiExpandedText = textView;
        textView.setTextSize(1, 16.0f);
        this.emojiExpandedText.setTextColor(-1);
        this.emojiExpandedText.setGravity(17);
        this.emojiExpandedText.setAlpha(0.0f);
        frameLayout.addView(this.emojiExpandedText, LayoutHelper.createFrame(-1.0f, -2.0f, 17, 10.0f, 32.0f, 10.0f, 0.0f));
        CorrectlyMeasuringTextView correctlyMeasuringTextView = new CorrectlyMeasuringTextView(this);
        this.hintTextView = correctlyMeasuringTextView;
        correctlyMeasuringTextView.setBackgroundDrawable(Theme.createRoundRectDrawable(AndroidUtilities.dp(3.0f), -231525581));
        this.hintTextView.setTextColor(Theme.getColor(Theme.key_chat_gifSaveHintText));
        this.hintTextView.setTextSize(1, 14.0f);
        this.hintTextView.setPadding(AndroidUtilities.dp(10.0f), AndroidUtilities.dp(10.0f), AndroidUtilities.dp(10.0f), AndroidUtilities.dp(10.0f));
        this.hintTextView.setGravity(17);
        this.hintTextView.setMaxWidth(AndroidUtilities.dp(300.0f));
        this.hintTextView.setAlpha(0.0f);
        frameLayout.addView(this.hintTextView, LayoutHelper.createFrame(-2.0f, -2.0f, 53, 0.0f, 42.0f, 10.0f, 0.0f));
        int ellMaxAlpha = this.stateText.getPaint().getAlpha();
        AnimatorSet animatorSet = new AnimatorSet();
        this.ellAnimator = animatorSet;
        animatorSet.playTogether(createAlphaAnimator(this.ellSpans[0], 0, ellMaxAlpha, 0, 300), createAlphaAnimator(this.ellSpans[1], 0, ellMaxAlpha, 150, 300), createAlphaAnimator(this.ellSpans[2], 0, ellMaxAlpha, 300, 300), createAlphaAnimator(this.ellSpans[0], ellMaxAlpha, 0, 1000, 400), createAlphaAnimator(this.ellSpans[1], ellMaxAlpha, 0, 1000, 400), createAlphaAnimator(this.ellSpans[2], ellMaxAlpha, 0, 1000, 400));
        this.ellAnimator.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.VoIPActivity.12
            private Runnable restarter = new Runnable() { // from class: im.uwrkaxlmjj.ui.VoIPActivity.12.1
                @Override // java.lang.Runnable
                public void run() {
                    if (!VoIPActivity.this.isFinishing()) {
                        VoIPActivity.this.ellAnimator.start();
                    }
                }
            };

            @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
            public void onAnimationEnd(Animator animation) {
                if (!VoIPActivity.this.isFinishing()) {
                    VoIPActivity.this.content.postDelayed(this.restarter, 300L);
                }
            }
        });
        frameLayout.setClipChildren(false);
        this.content = frameLayout;
        return frameLayout;
    }

    private ObjectAnimator createAlphaAnimator(Object target, int startVal, int endVal, int startDelay, int duration) {
        ObjectAnimator a = ObjectAnimator.ofInt(target, "alpha", startVal, endVal);
        a.setDuration(duration);
        a.setStartDelay(startDelay);
        a.setInterpolator(CubicBezierInterpolator.DEFAULT);
        return a;
    }

    @Override // android.app.Activity
    protected void onDestroy() {
        NotificationCenter.getGlobalInstance().removeObserver(this, NotificationCenter.emojiDidLoad);
        NotificationCenter.getGlobalInstance().removeObserver(this, NotificationCenter.closeInCallActivity);
        if (VoIPService.getSharedInstance() != null) {
            VoIPService.getSharedInstance().unregisterStateListener(this);
        }
        super.onDestroy();
    }

    @Override // android.app.Activity
    public void onBackPressed() {
        if (this.emojiExpanded) {
            setEmojiExpanded(false);
        } else if (!this.isIncomingWaiting) {
            super.onBackPressed();
        }
    }

    @Override // android.app.Activity
    protected void onResume() {
        super.onResume();
        if (VoIPService.getSharedInstance() != null) {
            VoIPService.getSharedInstance().onUIForegroundStateChanged(true);
        }
    }

    @Override // android.app.Activity
    protected void onPause() {
        super.onPause();
        if (this.retrying) {
            finish();
        }
        if (VoIPService.getSharedInstance() != null) {
            VoIPService.getSharedInstance().onUIForegroundStateChanged(false);
        }
    }

    @Override // android.app.Activity
    public void onRequestPermissionsResult(int requestCode, String[] permissions, int[] grantResults) {
        if (requestCode == 101) {
            if (VoIPService.getSharedInstance() == null) {
                finish();
                return;
            }
            if (grantResults.length > 0 && grantResults[0] == 0) {
                VoIPService.getSharedInstance().acceptIncomingCall();
                callAccepted();
            } else if (!shouldShowRequestPermissionRationale("android.permission.RECORD_AUDIO")) {
                VoIPService.getSharedInstance().declineIncomingCall();
                VoIPHelper.permissionDenied(this, new Runnable() { // from class: im.uwrkaxlmjj.ui.VoIPActivity.13
                    @Override // java.lang.Runnable
                    public void run() {
                        VoIPActivity.this.finish();
                    }
                });
            } else {
                this.acceptSwipe.reset();
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void updateKeyView() {
        if (VoIPService.getSharedInstance() == null) {
            return;
        }
        IdenticonDrawable img = new IdenticonDrawable();
        img.setColors(new int[]{ViewCompat.MEASURED_SIZE_MASK, -1, -1711276033, 872415231});
        TLRPC.EncryptedChat encryptedChat = new TLRPC.TL_encryptedChat();
        try {
            ByteArrayOutputStream buf = new ByteArrayOutputStream();
            buf.write(VoIPService.getSharedInstance().getEncryptionKey());
            buf.write(VoIPService.getSharedInstance().getGA());
            encryptedChat.auth_key = buf.toByteArray();
        } catch (Exception e) {
        }
        byte[] sha256 = Utilities.computeSHA256(encryptedChat.auth_key, 0, encryptedChat.auth_key.length);
        String[] emoji = EncryptionKeyEmojifier.emojifyForCall(sha256);
        this.emojiWrap.setContentDescription(LocaleController.getString("EncryptionKey", R.string.EncryptionKey) + ", " + TextUtils.join(", ", emoji));
        for (int i = 0; i < 4; i++) {
            Drawable drawable = Emoji.getEmojiDrawable(emoji[i]);
            if (drawable != null) {
                drawable.setBounds(0, 0, AndroidUtilities.dp(22.0f), AndroidUtilities.dp(22.0f));
                this.keyEmojiViews[i].setImageDrawable(drawable);
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public CharSequence getFormattedDebugString() {
        int iIndexOf;
        String in = VoIPService.getSharedInstance().getDebugString();
        SpannableString ss = new SpannableString(in);
        int offset = 0;
        do {
            int lineEnd = in.indexOf(10, offset + 1);
            if (lineEnd == -1) {
                lineEnd = in.length();
            }
            String line = in.substring(offset, lineEnd);
            if (line.contains("IN_USE")) {
                ss.setSpan(new ForegroundColorSpan(-16711936), offset, lineEnd, 0);
            } else if (line.contains(": ")) {
                ss.setSpan(new ForegroundColorSpan(-1426063361), offset, line.indexOf(58) + offset + 1, 0);
            }
            iIndexOf = in.indexOf(10, offset + 1);
            offset = iIndexOf;
        } while (iIndexOf != -1);
        return ss;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void showDebugAlert() {
        if (VoIPService.getSharedInstance() == null) {
            return;
        }
        VoIPService.getSharedInstance().forceRating();
        final LinearLayout linearLayout = new LinearLayout(this);
        linearLayout.setOrientation(1);
        linearLayout.setBackgroundColor(-872415232);
        int pad = AndroidUtilities.dp(16.0f);
        linearLayout.setPadding(pad, pad * 2, pad, pad * 2);
        TextView title = new TextView(this);
        title.setTextColor(-1);
        title.setTextSize(1, 15.0f);
        title.setTypeface(Typeface.DEFAULT_BOLD);
        title.setGravity(17);
        title.setText("libtgvoip v" + VoIPController.getVersion());
        linearLayout.addView(title, LayoutHelper.createLinear(-1, -2, 0.0f, 0.0f, 0.0f, 16.0f));
        ScrollView scroll = new ScrollView(this);
        final TextView debugText = new TextView(this);
        debugText.setTypeface(Typeface.MONOSPACE);
        debugText.setTextSize(1, 11.0f);
        debugText.setMaxWidth(AndroidUtilities.dp(350.0f));
        debugText.setTextColor(-1);
        debugText.setText(getFormattedDebugString());
        scroll.addView(debugText);
        linearLayout.addView(scroll, LayoutHelper.createLinear(-1, -1, 1.0f));
        TextView closeBtn = new TextView(this);
        closeBtn.setBackgroundColor(-1);
        closeBtn.setTextColor(-16777216);
        closeBtn.setPadding(pad, pad, pad, pad);
        closeBtn.setTextSize(1, 15.0f);
        closeBtn.setText(LocaleController.getString("Close", R.string.Close));
        linearLayout.addView(closeBtn, LayoutHelper.createLinear(-2, -2, 1, 0, 16, 0, 0));
        final WindowManager windowManager = (WindowManager) getSystemService("window");
        windowManager.addView(linearLayout, new WindowManager.LayoutParams(-1, -1, 1000, 0, -3));
        closeBtn.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.VoIPActivity.14
            @Override // android.view.View.OnClickListener
            public void onClick(View v) {
                windowManager.removeView(linearLayout);
            }
        });
        Runnable r = new Runnable() { // from class: im.uwrkaxlmjj.ui.VoIPActivity.15
            @Override // java.lang.Runnable
            public void run() {
                if (!VoIPActivity.this.isFinishing() && VoIPService.getSharedInstance() != null) {
                    debugText.setText(VoIPActivity.this.getFormattedDebugString());
                    linearLayout.postDelayed(this, 500L);
                }
            }
        };
        linearLayout.postDelayed(r, 500L);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void startUpdatingCallDuration() {
        Runnable r = new Runnable() { // from class: im.uwrkaxlmjj.ui.VoIPActivity.16
            @Override // java.lang.Runnable
            public void run() {
                if (!VoIPActivity.this.isFinishing() && VoIPService.getSharedInstance() != null) {
                    if (VoIPActivity.this.callState == 3 || VoIPActivity.this.callState == 5) {
                        long duration = VoIPService.getSharedInstance().getCallDuration() / 1000;
                        VoIPActivity.this.durationText.setText(duration > 3600 ? String.format("%d:%02d:%02d", Long.valueOf(duration / 3600), Long.valueOf((duration % 3600) / 60), Long.valueOf(duration % 60)) : String.format("%d:%02d", Long.valueOf(duration / 60), Long.valueOf(duration % 60)));
                        VoIPActivity.this.durationText.postDelayed(this, 500L);
                    }
                }
            }
        };
        r.run();
    }

    @Override // android.app.Activity, android.view.KeyEvent.Callback
    public boolean onKeyDown(int keyCode, KeyEvent event) {
        if (this.isIncomingWaiting && (keyCode == 25 || keyCode == 24)) {
            if (VoIPService.getSharedInstance() != null) {
                VoIPService.getSharedInstance().stopRinging();
                return true;
            }
            finish();
            return true;
        }
        return super.onKeyDown(keyCode, event);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void callAccepted() {
        ObjectAnimator colorAnim;
        this.endBtn.setVisibility(0);
        if (VoIPService.getSharedInstance().hasEarpiece()) {
            this.spkToggle.setVisibility(0);
        } else {
            this.spkToggle.setVisibility(8);
        }
        this.bottomButtons.setVisibility(0);
        if (this.didAcceptFromHere) {
            this.acceptBtn.setVisibility(8);
            if (Build.VERSION.SDK_INT >= 21) {
                colorAnim = ObjectAnimator.ofArgb(this.endBtnBg, TtmlNode.ATTR_TTS_COLOR, -12207027, -1696188);
            } else {
                colorAnim = ObjectAnimator.ofInt(this.endBtnBg, TtmlNode.ATTR_TTS_COLOR, -12207027, -1696188);
                colorAnim.setEvaluator(new ArgbEvaluator());
            }
            AnimatorSet set = new AnimatorSet();
            AnimatorSet decSet = new AnimatorSet();
            decSet.playTogether(ObjectAnimator.ofFloat(this.endBtnIcon, "rotation", -135.0f, 0.0f), colorAnim);
            decSet.setInterpolator(CubicBezierInterpolator.EASE_OUT);
            decSet.setDuration(500L);
            AnimatorSet accSet = new AnimatorSet();
            accSet.playTogether(ObjectAnimator.ofFloat(this.swipeViewsWrap, "alpha", 1.0f, 0.0f), ObjectAnimator.ofFloat(this.declineBtn, "alpha", 0.0f), ObjectAnimator.ofFloat(this.accountNameText, "alpha", 0.0f));
            accSet.setInterpolator(CubicBezierInterpolator.EASE_IN);
            accSet.setDuration(125L);
            set.playTogether(decSet, accSet);
            set.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.VoIPActivity.17
                @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                public void onAnimationEnd(Animator animation) {
                    VoIPActivity.this.swipeViewsWrap.setVisibility(8);
                    VoIPActivity.this.declineBtn.setVisibility(8);
                    VoIPActivity.this.accountNameText.setVisibility(8);
                }
            });
            set.start();
            return;
        }
        AnimatorSet set2 = new AnimatorSet();
        AnimatorSet decSet2 = new AnimatorSet();
        decSet2.playTogether(ObjectAnimator.ofFloat(this.bottomButtons, "alpha", 0.0f, 1.0f));
        decSet2.setInterpolator(CubicBezierInterpolator.EASE_OUT);
        decSet2.setDuration(500L);
        AnimatorSet accSet2 = new AnimatorSet();
        accSet2.playTogether(ObjectAnimator.ofFloat(this.swipeViewsWrap, "alpha", 1.0f, 0.0f), ObjectAnimator.ofFloat(this.declineBtn, "alpha", 0.0f), ObjectAnimator.ofFloat(this.acceptBtn, "alpha", 0.0f), ObjectAnimator.ofFloat(this.accountNameText, "alpha", 0.0f));
        accSet2.setInterpolator(CubicBezierInterpolator.EASE_IN);
        accSet2.setDuration(125L);
        set2.playTogether(decSet2, accSet2);
        set2.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.VoIPActivity.18
            @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
            public void onAnimationEnd(Animator animation) {
                VoIPActivity.this.swipeViewsWrap.setVisibility(8);
                VoIPActivity.this.declineBtn.setVisibility(8);
                VoIPActivity.this.acceptBtn.setVisibility(8);
                VoIPActivity.this.accountNameText.setVisibility(8);
            }
        });
        set2.start();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void showRetry() {
        ObjectAnimator colorAnim;
        AnimatorSet animatorSet = this.retryAnim;
        if (animatorSet != null) {
            animatorSet.cancel();
        }
        this.endBtn.setEnabled(false);
        this.retrying = true;
        this.cancelBtn.setVisibility(0);
        this.cancelBtn.setAlpha(0.0f);
        AnimatorSet set = new AnimatorSet();
        if (Build.VERSION.SDK_INT >= 21) {
            colorAnim = ObjectAnimator.ofArgb(this.endBtnBg, TtmlNode.ATTR_TTS_COLOR, -1696188, -12207027);
        } else {
            colorAnim = ObjectAnimator.ofInt(this.endBtnBg, TtmlNode.ATTR_TTS_COLOR, -1696188, -12207027);
            colorAnim.setEvaluator(new ArgbEvaluator());
        }
        set.playTogether(ObjectAnimator.ofFloat(this.cancelBtn, "alpha", 0.0f, 1.0f), ObjectAnimator.ofFloat(this.endBtn, "translationX", 0.0f, ((this.content.getWidth() / 2) - AndroidUtilities.dp(52.0f)) - (this.endBtn.getWidth() / 2)), colorAnim, ObjectAnimator.ofFloat(this.endBtnIcon, "rotation", 0.0f, -135.0f));
        set.setStartDelay(200L);
        set.setDuration(300L);
        set.setInterpolator(CubicBezierInterpolator.DEFAULT);
        set.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.VoIPActivity.19
            @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
            public void onAnimationEnd(Animator animation) {
                VoIPActivity.this.retryAnim = null;
                VoIPActivity.this.endBtn.setEnabled(true);
            }
        });
        this.retryAnim = set;
        set.start();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void hideRetry() {
        ObjectAnimator colorAnim;
        AnimatorSet animatorSet = this.retryAnim;
        if (animatorSet != null) {
            animatorSet.cancel();
        }
        this.retrying = false;
        if (Build.VERSION.SDK_INT >= 21) {
            colorAnim = ObjectAnimator.ofArgb(this.endBtnBg, TtmlNode.ATTR_TTS_COLOR, -12207027, -1696188);
        } else {
            colorAnim = ObjectAnimator.ofInt(this.endBtnBg, TtmlNode.ATTR_TTS_COLOR, -12207027, -1696188);
            colorAnim.setEvaluator(new ArgbEvaluator());
        }
        AnimatorSet set = new AnimatorSet();
        set.playTogether(colorAnim, ObjectAnimator.ofFloat(this.endBtnIcon, "rotation", -135.0f, 0.0f), ObjectAnimator.ofFloat(this.endBtn, "translationX", 0.0f), ObjectAnimator.ofFloat(this.cancelBtn, "alpha", 0.0f));
        set.setStartDelay(200L);
        set.setDuration(300L);
        set.setInterpolator(CubicBezierInterpolator.DEFAULT);
        set.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.VoIPActivity.20
            @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
            public void onAnimationEnd(Animator animation) {
                VoIPActivity.this.cancelBtn.setVisibility(8);
                VoIPActivity.this.endBtn.setEnabled(true);
                VoIPActivity.this.retryAnim = null;
            }
        });
        this.retryAnim = set;
        set.start();
    }

    @Override // im.uwrkaxlmjj.messenger.voip.VoIPBaseService.StateListener
    public void onStateChanged(final int state) {
        final int prevState = this.callState;
        this.callState = state;
        runOnUiThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.VoIPActivity.21
            @Override // java.lang.Runnable
            public void run() {
                int count;
                int i;
                boolean wasFirstStateChange = VoIPActivity.this.firstStateChange;
                if (VoIPActivity.this.firstStateChange) {
                    VoIPActivity.this.spkToggle.setChecked(((AudioManager) VoIPActivity.this.getSystemService("audio")).isSpeakerphoneOn());
                    if (VoIPActivity.this.isIncomingWaiting = state == 15) {
                        VoIPActivity.this.swipeViewsWrap.setVisibility(0);
                        VoIPActivity.this.endBtn.setVisibility(8);
                        VoIPActivity.this.acceptSwipe.startAnimatingArrows();
                        VoIPActivity.this.declineSwipe.startAnimatingArrows();
                        if (UserConfig.getActivatedAccountsCount() > 1) {
                            TLRPC.User self = UserConfig.getInstance(VoIPActivity.this.currentAccount).getCurrentUser();
                            VoIPActivity.this.accountNameText.setText(LocaleController.formatString("VoipAnsweringAsAccount", R.string.VoipAnsweringAsAccount, ContactsController.formatName(self.first_name, self.last_name)));
                        } else {
                            VoIPActivity.this.accountNameText.setVisibility(8);
                        }
                        VoIPActivity.this.getWindow().addFlags(2097152);
                        VoIPService svc = VoIPService.getSharedInstance();
                        if (svc != null) {
                            svc.startRingtoneAndVibration();
                        }
                        VoIPActivity.this.setTitle(LocaleController.getString("VoipIncoming", R.string.VoipIncoming));
                    } else {
                        VoIPActivity.this.swipeViewsWrap.setVisibility(8);
                        VoIPActivity.this.acceptBtn.setVisibility(8);
                        VoIPActivity.this.declineBtn.setVisibility(8);
                        VoIPActivity.this.accountNameText.setVisibility(8);
                        VoIPActivity.this.getWindow().clearFlags(2097152);
                    }
                    if (state != 3) {
                        VoIPActivity.this.emojiWrap.setVisibility(8);
                    }
                    VoIPActivity.this.firstStateChange = false;
                }
                if (VoIPActivity.this.isIncomingWaiting && (i = state) != 15 && i != 11 && i != 10) {
                    VoIPActivity.this.isIncomingWaiting = false;
                    if (!VoIPActivity.this.didAcceptFromHere) {
                        VoIPActivity.this.callAccepted();
                    }
                }
                int i2 = state;
                if (i2 == 15) {
                    VoIPActivity.this.setStateTextAnimated(LocaleController.getString("VoipIncoming", R.string.VoipIncoming), false);
                    VoIPActivity.this.getWindow().addFlags(2097152);
                } else if (i2 == 1 || i2 == 2) {
                    VoIPActivity.this.setStateTextAnimated(LocaleController.getString("VoipConnecting", R.string.VoipConnecting), true);
                } else if (i2 == 12) {
                    VoIPActivity.this.setStateTextAnimated(LocaleController.getString("VoipExchangingKeys", R.string.VoipExchangingKeys), true);
                } else if (i2 == 13) {
                    VoIPActivity.this.setStateTextAnimated(LocaleController.getString("VoipWaiting", R.string.VoipWaiting), true);
                } else if (i2 == 16) {
                    VoIPActivity.this.setStateTextAnimated(LocaleController.getString("VoipRinging", R.string.VoipRinging), true);
                } else if (i2 == 14) {
                    VoIPActivity.this.setStateTextAnimated(LocaleController.getString("VoipRequesting", R.string.VoipRequesting), true);
                } else if (i2 == 10) {
                    VoIPActivity.this.setStateTextAnimated(LocaleController.getString("VoipHangingUp", R.string.VoipHangingUp), true);
                    VoIPActivity.this.endBtnIcon.setAlpha(0.5f);
                    VoIPActivity.this.endBtn.setEnabled(false);
                } else if (i2 == 11) {
                    VoIPActivity.this.setStateTextAnimated(LocaleController.getString("VoipCallEnded", R.string.VoipCallEnded), false);
                    VoIPActivity.this.stateText.postDelayed(new Runnable() { // from class: im.uwrkaxlmjj.ui.VoIPActivity.21.1
                        @Override // java.lang.Runnable
                        public void run() {
                            VoIPActivity.this.finish();
                        }
                    }, 200L);
                } else if (i2 == 17) {
                    VoIPActivity.this.setStateTextAnimated(LocaleController.getString("VoipBusy", R.string.VoipBusy), false);
                    VoIPActivity.this.showRetry();
                } else if (i2 == 3 || i2 == 5) {
                    VoIPActivity.this.setTitle((CharSequence) null);
                    if (!wasFirstStateChange && state == 3 && (count = MessagesController.getGlobalMainSettings().getInt("call_emoji_tooltip_count", 0)) < 3) {
                        VoIPActivity.this.setEmojiTooltipVisible(true);
                        VoIPActivity.this.hintTextView.postDelayed(VoIPActivity.this.tooltipHider = new Runnable() { // from class: im.uwrkaxlmjj.ui.VoIPActivity.21.2
                            @Override // java.lang.Runnable
                            public void run() {
                                VoIPActivity.this.tooltipHider = null;
                                VoIPActivity.this.setEmojiTooltipVisible(false);
                            }
                        }, DefaultRenderersFactory.DEFAULT_ALLOWED_VIDEO_JOINING_TIME_MS);
                        MessagesController.getGlobalMainSettings().edit().putInt("call_emoji_tooltip_count", count + 1).commit();
                    }
                    int count2 = prevState;
                    if (count2 != 3 && count2 != 5) {
                        VoIPActivity.this.setStateTextAnimated("0:00", false);
                        VoIPActivity.this.startUpdatingCallDuration();
                        VoIPActivity.this.updateKeyView();
                        if (VoIPActivity.this.emojiWrap.getVisibility() != 0) {
                            VoIPActivity.this.emojiWrap.setVisibility(0);
                            VoIPActivity.this.emojiWrap.setAlpha(0.0f);
                            VoIPActivity.this.emojiWrap.animate().alpha(1.0f).setDuration(200L).setInterpolator(new DecelerateInterpolator()).start();
                        }
                    }
                } else if (i2 == 4) {
                    VoIPActivity.this.setStateTextAnimated(LocaleController.getString("VoipFailed", R.string.VoipFailed), false);
                    int lastError = VoIPService.getSharedInstance() != null ? VoIPService.getSharedInstance().getLastError() : 0;
                    if (lastError == 1) {
                        VoIPActivity voIPActivity = VoIPActivity.this;
                        voIPActivity.showErrorDialog(AndroidUtilities.replaceTags(LocaleController.formatString("VoipPeerIncompatible", R.string.VoipPeerIncompatible, ContactsController.formatName(voIPActivity.user.first_name, VoIPActivity.this.user.last_name))));
                    } else if (lastError == -1) {
                        VoIPActivity voIPActivity2 = VoIPActivity.this;
                        voIPActivity2.showErrorDialog(AndroidUtilities.replaceTags(LocaleController.formatString("VoipPeerOutdated", R.string.VoipPeerOutdated, ContactsController.formatName(voIPActivity2.user.first_name, VoIPActivity.this.user.last_name))));
                    } else if (lastError == -2) {
                        VoIPActivity voIPActivity3 = VoIPActivity.this;
                        voIPActivity3.showErrorDialog(AndroidUtilities.replaceTags(LocaleController.formatString("CallNotAvailable", R.string.CallNotAvailable, ContactsController.formatName(voIPActivity3.user.first_name, VoIPActivity.this.user.last_name))));
                    } else if (lastError == 3) {
                        VoIPActivity.this.showErrorDialog("Error initializing audio hardware");
                    } else if (lastError == -3) {
                        VoIPActivity.this.finish();
                    } else if (lastError == -5) {
                        VoIPActivity.this.showErrorDialog(LocaleController.getString("VoipErrorUnknown", R.string.VoipErrorUnknown));
                    } else {
                        VoIPActivity.this.stateText.postDelayed(new Runnable() { // from class: im.uwrkaxlmjj.ui.VoIPActivity.21.3
                            @Override // java.lang.Runnable
                            public void run() {
                                VoIPActivity.this.finish();
                            }
                        }, 1000L);
                    }
                }
                VoIPActivity.this.brandingText.invalidate();
            }
        });
    }

    @Override // im.uwrkaxlmjj.messenger.voip.VoIPBaseService.StateListener
    public void onSignalBarsCountChanged(final int count) {
        runOnUiThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.VoIPActivity.22
            @Override // java.lang.Runnable
            public void run() {
                VoIPActivity.this.signalBarsCount = count;
                VoIPActivity.this.brandingText.invalidate();
            }
        });
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void showErrorDialog(CharSequence message) {
        AlertDialog dlg = new DarkAlertDialog.Builder(this).setTitle(LocaleController.getString("VoipFailed", R.string.VoipFailed)).setMessage(message).setPositiveButton(LocaleController.getString("OK", R.string.OK), null).show();
        dlg.setCanceledOnTouchOutside(true);
        dlg.setOnDismissListener(new DialogInterface.OnDismissListener() { // from class: im.uwrkaxlmjj.ui.VoIPActivity.23
            @Override // android.content.DialogInterface.OnDismissListener
            public void onDismiss(DialogInterface dialog) {
                VoIPActivity.this.finish();
            }
        });
    }

    @Override // im.uwrkaxlmjj.messenger.voip.VoIPBaseService.StateListener
    public void onAudioSettingsChanged() {
        VoIPBaseService svc = VoIPBaseService.getSharedInstance();
        if (svc == null) {
            return;
        }
        this.micToggle.setChecked(svc.isMicMute());
        if (!svc.hasEarpiece() && !svc.isBluetoothHeadsetConnected()) {
            this.spkToggle.setVisibility(4);
            return;
        }
        this.spkToggle.setVisibility(0);
        if (!svc.hasEarpiece()) {
            this.spkToggle.setImageResource(R.drawable.ic_bluetooth_white_24dp);
            this.spkToggle.setChecked(svc.isSpeakerphoneOn());
            return;
        }
        if (svc.isBluetoothHeadsetConnected()) {
            int currentAudioRoute = svc.getCurrentAudioRoute();
            if (currentAudioRoute == 0) {
                this.spkToggle.setImageResource(R.drawable.ic_phone_in_talk_white_24dp);
            } else if (currentAudioRoute == 1) {
                this.spkToggle.setImageResource(R.drawable.ic_volume_up_white_24dp);
            } else if (currentAudioRoute == 2) {
                this.spkToggle.setImageResource(R.drawable.ic_bluetooth_white_24dp);
            }
            this.spkToggle.setChecked(false);
            return;
        }
        this.spkToggle.setImageResource(R.drawable.ic_volume_up_white_24dp);
        this.spkToggle.setChecked(svc.isSpeakerphoneOn());
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void setStateTextAnimated(String str, boolean z) {
        CharSequence upperCase;
        if (str.equals(this.lastStateText)) {
            return;
        }
        this.lastStateText = str;
        Animator animator = this.textChangingAnim;
        if (animator != null) {
            animator.cancel();
        }
        if (z) {
            if (!this.ellAnimator.isRunning()) {
                this.ellAnimator.start();
            }
            SpannableStringBuilder spannableStringBuilder = new SpannableStringBuilder(str.toUpperCase());
            for (TextAlphaSpan textAlphaSpan : this.ellSpans) {
                textAlphaSpan.setAlpha(0);
            }
            SpannableString spannableString = new SpannableString("...");
            spannableString.setSpan(this.ellSpans[0], 0, 1, 0);
            spannableString.setSpan(this.ellSpans[1], 1, 2, 0);
            spannableString.setSpan(this.ellSpans[2], 2, 3, 0);
            spannableStringBuilder.append((CharSequence) spannableString);
            upperCase = spannableStringBuilder;
        } else {
            if (this.ellAnimator.isRunning()) {
                this.ellAnimator.cancel();
            }
            upperCase = str.toUpperCase();
        }
        this.stateText2.setText(upperCase);
        this.stateText2.setVisibility(0);
        this.stateText.setPivotX(LocaleController.isRTL ? this.stateText.getWidth() : 0.0f);
        this.stateText.setPivotY(r7.getHeight() / 2);
        this.stateText2.setPivotX(LocaleController.isRTL ? this.stateText.getWidth() : 0.0f);
        this.stateText2.setPivotY(this.stateText.getHeight() / 2);
        this.durationText = this.stateText2;
        AnimatorSet animatorSet = new AnimatorSet();
        animatorSet.playTogether(ObjectAnimator.ofFloat(this.stateText2, "alpha", 0.0f, 1.0f), ObjectAnimator.ofFloat(this.stateText2, "translationY", this.stateText.getHeight() / 2, 0.0f), ObjectAnimator.ofFloat(this.stateText2, "scaleX", 0.7f, 1.0f), ObjectAnimator.ofFloat(this.stateText2, "scaleY", 0.7f, 1.0f), ObjectAnimator.ofFloat(this.stateText, "alpha", 1.0f, 0.0f), ObjectAnimator.ofFloat(this.stateText, "translationY", 0.0f, (-r10.getHeight()) / 2), ObjectAnimator.ofFloat(this.stateText, "scaleX", 1.0f, 0.7f), ObjectAnimator.ofFloat(this.stateText, "scaleY", 1.0f, 0.7f));
        animatorSet.setDuration(200L);
        animatorSet.setInterpolator(CubicBezierInterpolator.DEFAULT);
        animatorSet.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.VoIPActivity.24
            @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
            public void onAnimationEnd(Animator animation) {
                VoIPActivity.this.textChangingAnim = null;
                VoIPActivity.this.stateText2.setVisibility(8);
                VoIPActivity voIPActivity = VoIPActivity.this;
                voIPActivity.durationText = voIPActivity.stateText;
                VoIPActivity.this.stateText.setTranslationY(0.0f);
                VoIPActivity.this.stateText.setScaleX(1.0f);
                VoIPActivity.this.stateText.setScaleY(1.0f);
                VoIPActivity.this.stateText.setAlpha(1.0f);
                VoIPActivity.this.stateText.setText(VoIPActivity.this.stateText2.getText());
            }
        });
        this.textChangingAnim = animatorSet;
        animatorSet.start();
    }

    @Override // im.uwrkaxlmjj.messenger.NotificationCenter.NotificationCenterDelegate
    public void didReceivedNotification(int id, int account, Object... args) {
        if (id == NotificationCenter.emojiDidLoad) {
            for (ImageView iv : this.keyEmojiViews) {
                iv.invalidate();
            }
        }
        if (id == NotificationCenter.closeInCallActivity) {
            finish();
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void setEmojiTooltipVisible(boolean visible) {
        this.emojiTooltipVisible = visible;
        Animator animator = this.tooltipAnim;
        if (animator != null) {
            animator.cancel();
        }
        this.hintTextView.setVisibility(0);
        TextView textView = this.hintTextView;
        float[] fArr = new float[1];
        fArr[0] = visible ? 1.0f : 0.0f;
        ObjectAnimator oa = ObjectAnimator.ofFloat(textView, "alpha", fArr);
        oa.setDuration(300L);
        oa.setInterpolator(CubicBezierInterpolator.DEFAULT);
        oa.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.VoIPActivity.25
            @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
            public void onAnimationEnd(Animator animation) {
                VoIPActivity.this.tooltipAnim = null;
            }
        });
        this.tooltipAnim = oa;
        oa.start();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void setEmojiExpanded(boolean expanded) {
        if (this.emojiExpanded == expanded) {
            return;
        }
        this.emojiExpanded = expanded;
        AnimatorSet animatorSet = this.emojiAnimator;
        if (animatorSet != null) {
            animatorSet.cancel();
        }
        if (expanded) {
            int[] loc = {0, 0};
            int[] loc2 = {0, 0};
            this.emojiWrap.getLocationInWindow(loc);
            this.emojiExpandedText.getLocationInWindow(loc2);
            Rect rect = new Rect();
            getWindow().getDecorView().getGlobalVisibleRect(rect);
            int offsetY = ((loc2[1] - (loc[1] + this.emojiWrap.getHeight())) - AndroidUtilities.dp(32.0f)) - this.emojiWrap.getHeight();
            int firstOffsetX = ((rect.width() / 2) - (Math.round(this.emojiWrap.getWidth() * 2.5f) / 2)) - loc[0];
            AnimatorSet set = new AnimatorSet();
            ImageView imageView = this.blurOverlayView1;
            float[] fArr = {imageView.getAlpha(), 1.0f, 1.0f};
            ImageView imageView2 = this.blurOverlayView2;
            set.playTogether(ObjectAnimator.ofFloat(this.emojiWrap, "translationY", offsetY), ObjectAnimator.ofFloat(this.emojiWrap, "translationX", firstOffsetX), ObjectAnimator.ofFloat(this.emojiWrap, "scaleX", 2.5f), ObjectAnimator.ofFloat(this.emojiWrap, "scaleY", 2.5f), ObjectAnimator.ofFloat(imageView, "alpha", fArr), ObjectAnimator.ofFloat(imageView2, "alpha", imageView2.getAlpha(), this.blurOverlayView2.getAlpha(), 1.0f), ObjectAnimator.ofFloat(this.emojiExpandedText, "alpha", 1.0f));
            set.setDuration(300L);
            set.setInterpolator(CubicBezierInterpolator.DEFAULT);
            this.emojiAnimator = set;
            set.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.VoIPActivity.26
                @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                public void onAnimationEnd(Animator animation) {
                    VoIPActivity.this.emojiAnimator = null;
                }
            });
            set.start();
            return;
        }
        AnimatorSet set2 = new AnimatorSet();
        ImageView imageView3 = this.blurOverlayView1;
        float[] fArr2 = {imageView3.getAlpha(), this.blurOverlayView1.getAlpha(), 0.0f};
        ImageView imageView4 = this.blurOverlayView2;
        set2.playTogether(ObjectAnimator.ofFloat(this.emojiWrap, "translationX", 0.0f), ObjectAnimator.ofFloat(this.emojiWrap, "translationY", 0.0f), ObjectAnimator.ofFloat(this.emojiWrap, "scaleX", 1.0f), ObjectAnimator.ofFloat(this.emojiWrap, "scaleY", 1.0f), ObjectAnimator.ofFloat(imageView3, "alpha", fArr2), ObjectAnimator.ofFloat(imageView4, "alpha", imageView4.getAlpha(), 0.0f, 0.0f), ObjectAnimator.ofFloat(this.emojiExpandedText, "alpha", 0.0f));
        set2.setDuration(300L);
        set2.setInterpolator(CubicBezierInterpolator.DEFAULT);
        this.emojiAnimator = set2;
        set2.addListener(new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.VoIPActivity.27
            @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
            public void onAnimationEnd(Animator animation) {
                VoIPActivity.this.emojiAnimator = null;
            }
        });
        set2.start();
    }

    /* JADX INFO: renamed from: im.uwrkaxlmjj.ui.VoIPActivity$28, reason: invalid class name */
    class AnonymousClass28 implements Runnable {
        final /* synthetic */ ImageReceiver.BitmapHolder val$src;

        AnonymousClass28(ImageReceiver.BitmapHolder bitmapHolder) {
            this.val$src = bitmapHolder;
        }

        @Override // java.lang.Runnable
        public void run() {
            try {
                Bitmap blur1 = Bitmap.createBitmap(150, 150, Bitmap.Config.ARGB_8888);
                Canvas canvas = new Canvas(blur1);
                canvas.drawBitmap(this.val$src.bitmap, (Rect) null, new Rect(0, 0, 150, 150), new Paint(2));
                Utilities.blurBitmap(blur1, 3, 0, blur1.getWidth(), blur1.getHeight(), blur1.getRowBytes());
                Palette palette = Palette.from(this.val$src.bitmap).generate();
                Paint paint = new Paint();
                paint.setColor((palette.getDarkMutedColor(-11242343) & ViewCompat.MEASURED_SIZE_MASK) | 1140850688);
                canvas.drawColor(637534208);
                canvas.drawRect(0.0f, 0.0f, canvas.getWidth(), canvas.getHeight(), paint);
                Bitmap blur2 = Bitmap.createBitmap(50, 50, Bitmap.Config.ARGB_8888);
                Canvas canvas2 = new Canvas(blur2);
                canvas2.drawBitmap(this.val$src.bitmap, (Rect) null, new Rect(0, 0, 50, 50), new Paint(2));
                Utilities.blurBitmap(blur2, 3, 0, blur2.getWidth(), blur2.getHeight(), blur2.getRowBytes());
                paint.setAlpha(102);
                canvas2.drawRect(0.0f, 0.0f, canvas2.getWidth(), canvas2.getHeight(), paint);
                VoIPActivity.this.blurredPhoto1 = blur1;
                VoIPActivity.this.blurredPhoto2 = blur2;
                VoIPActivity voIPActivity = VoIPActivity.this;
                final ImageReceiver.BitmapHolder bitmapHolder = this.val$src;
                voIPActivity.runOnUiThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$VoIPActivity$28$q2f_QQPiSRsfdE6Zu-mQEPjAwXM
                    @Override // java.lang.Runnable
                    public final void run() {
                        this.f$0.lambda$run$0$VoIPActivity$28(bitmapHolder);
                    }
                });
            } catch (Throwable th) {
            }
        }

        public /* synthetic */ void lambda$run$0$VoIPActivity$28(ImageReceiver.BitmapHolder src) {
            VoIPActivity.this.blurOverlayView1.setImageBitmap(VoIPActivity.this.blurredPhoto1);
            VoIPActivity.this.blurOverlayView2.setImageBitmap(VoIPActivity.this.blurredPhoto2);
            src.release();
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void updateBlurredPhotos(ImageReceiver.BitmapHolder src) {
        new Thread(new AnonymousClass28(src)).start();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void sendTextMessage(final String text) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$VoIPActivity$5D_BEfBYMexn0RVqxvNLJqwA7Fk
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$sendTextMessage$3$VoIPActivity(text);
            }
        });
    }

    public /* synthetic */ void lambda$sendTextMessage$3$VoIPActivity(String text) {
        SendMessagesHelper.getInstance(this.currentAccount).sendMessage(text, this.user.id, null, null, false, null, null, null, true, 0);
    }

    private void showMessagesSheet() {
        if (VoIPService.getSharedInstance() != null) {
            VoIPService.getSharedInstance().stopRinging();
        }
        SharedPreferences prefs = getSharedPreferences("mainconfig", 0);
        String[] msgs = {prefs.getString("quick_reply_msg1", LocaleController.getString("QuickReplyDefault1", R.string.QuickReplyDefault1)), prefs.getString("quick_reply_msg2", LocaleController.getString("QuickReplyDefault2", R.string.QuickReplyDefault2)), prefs.getString("quick_reply_msg3", LocaleController.getString("QuickReplyDefault3", R.string.QuickReplyDefault3)), prefs.getString("quick_reply_msg4", LocaleController.getString("QuickReplyDefault4", R.string.QuickReplyDefault4))};
        LinearLayout linearLayout = new LinearLayout(this);
        linearLayout.setOrientation(1);
        final BottomSheet bottomSheet = new BottomSheet(this, true, 0);
        if (Build.VERSION.SDK_INT >= 21) {
            getWindow().setNavigationBarColor(-13948117);
            bottomSheet.setOnDismissListener(new DialogInterface.OnDismissListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$VoIPActivity$vaOS_01k_WpZAzKbLuN-O9AwAZI
                @Override // android.content.DialogInterface.OnDismissListener
                public final void onDismiss(DialogInterface dialogInterface) {
                    this.f$0.lambda$showMessagesSheet$4$VoIPActivity(dialogInterface);
                }
            });
        }
        View.OnClickListener listener = new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$VoIPActivity$B9L8fhaP1Qau1Ybm-3nx8gGNDik
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                this.f$0.lambda$showMessagesSheet$6$VoIPActivity(bottomSheet, view);
            }
        };
        for (String msg : msgs) {
            BottomSheet.BottomSheetCell cell = new BottomSheet.BottomSheetCell(this, 0);
            cell.setTextAndIcon(msg, 0);
            cell.setTextColor(-1);
            cell.setTag(msg);
            cell.setOnClickListener(listener);
            linearLayout.addView(cell);
        }
        FrameLayout frameLayout = new FrameLayout(this);
        final BottomSheet.BottomSheetCell cell2 = new BottomSheet.BottomSheetCell(this, 0);
        cell2.setTextAndIcon(LocaleController.getString("QuickReplyCustom", R.string.QuickReplyCustom), 0);
        cell2.setTextColor(-1);
        frameLayout.addView(cell2);
        final FrameLayout editor = new FrameLayout(this);
        final EditText field = new EditText(this);
        field.setTextSize(1, 16.0f);
        field.setTextColor(-1);
        field.setHintTextColor(DarkTheme.getColor(Theme.key_chat_messagePanelHint));
        field.setBackgroundDrawable(null);
        field.setPadding(AndroidUtilities.dp(16.0f), AndroidUtilities.dp(11.0f), AndroidUtilities.dp(16.0f), AndroidUtilities.dp(12.0f));
        field.setHint(LocaleController.getString("QuickReplyCustom", R.string.QuickReplyCustom));
        field.setMinHeight(AndroidUtilities.dp(48.0f));
        field.setGravity(80);
        field.setMaxLines(4);
        field.setSingleLine(false);
        field.setInputType(field.getInputType() | 16384 | 131072);
        editor.addView(field, LayoutHelper.createFrame(-1.0f, -2.0f, LocaleController.isRTL ? 5 : 3, LocaleController.isRTL ? 48.0f : 0.0f, 0.0f, LocaleController.isRTL ? 0.0f : 48.0f, 0.0f));
        final ImageView sendBtn = new ImageView(this);
        sendBtn.setScaleType(ImageView.ScaleType.CENTER);
        sendBtn.setImageDrawable(DarkTheme.getThemedDrawable(this, R.drawable.ic_send, Theme.key_chat_messagePanelSend));
        if (LocaleController.isRTL) {
            sendBtn.setScaleX(-0.1f);
        } else {
            sendBtn.setScaleX(0.1f);
        }
        sendBtn.setScaleY(0.1f);
        sendBtn.setAlpha(0.0f);
        editor.addView(sendBtn, LayoutHelper.createFrame(48, 48, (LocaleController.isRTL ? 3 : 5) | 80));
        sendBtn.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$VoIPActivity$WqbYpHgfEEjEMTIpUXWRVqaEVGo
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                this.f$0.lambda$showMessagesSheet$7$VoIPActivity(field, bottomSheet, view);
            }
        });
        sendBtn.setVisibility(4);
        final ImageView cancelBtn = new ImageView(this);
        cancelBtn.setScaleType(ImageView.ScaleType.CENTER);
        cancelBtn.setImageDrawable(DarkTheme.getThemedDrawable(this, R.drawable.edit_cancel, Theme.key_chat_messagePanelIcons));
        editor.addView(cancelBtn, LayoutHelper.createFrame(48, 48, (LocaleController.isRTL ? 3 : 5) | 80));
        cancelBtn.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$VoIPActivity$8G90ylnhAIEEnVu-jOaBp0KFRTY
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                this.f$0.lambda$showMessagesSheet$8$VoIPActivity(editor, cell2, field, view);
            }
        });
        field.addTextChangedListener(new TextWatcher() { // from class: im.uwrkaxlmjj.ui.VoIPActivity.30
            boolean prevState = false;

            @Override // android.text.TextWatcher
            public void beforeTextChanged(CharSequence s, int start, int count, int after) {
            }

            @Override // android.text.TextWatcher
            public void onTextChanged(CharSequence s, int start, int before, int count) {
            }

            @Override // android.text.TextWatcher
            public void afterTextChanged(Editable s) {
                boolean hasText = s.length() > 0;
                if (this.prevState != hasText) {
                    this.prevState = hasText;
                    if (hasText) {
                        sendBtn.setVisibility(0);
                        sendBtn.animate().alpha(1.0f).scaleX(LocaleController.isRTL ? -1.0f : 1.0f).scaleY(1.0f).setDuration(200L).setInterpolator(CubicBezierInterpolator.DEFAULT).start();
                        cancelBtn.animate().alpha(0.0f).scaleX(0.1f).scaleY(0.1f).setInterpolator(CubicBezierInterpolator.DEFAULT).setDuration(200L).withEndAction(new Runnable() { // from class: im.uwrkaxlmjj.ui.VoIPActivity.30.1
                            @Override // java.lang.Runnable
                            public void run() {
                                cancelBtn.setVisibility(4);
                            }
                        }).start();
                    } else {
                        cancelBtn.setVisibility(0);
                        cancelBtn.animate().alpha(1.0f).scaleX(1.0f).scaleY(1.0f).setDuration(200L).setInterpolator(CubicBezierInterpolator.DEFAULT).start();
                        sendBtn.animate().alpha(0.0f).scaleX(LocaleController.isRTL ? -0.1f : 0.1f).scaleY(0.1f).setInterpolator(CubicBezierInterpolator.DEFAULT).setDuration(200L).withEndAction(new Runnable() { // from class: im.uwrkaxlmjj.ui.VoIPActivity.30.2
                            @Override // java.lang.Runnable
                            public void run() {
                                sendBtn.setVisibility(4);
                            }
                        }).start();
                    }
                }
            }
        });
        editor.setVisibility(8);
        frameLayout.addView(editor);
        cell2.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$VoIPActivity$Zh4VlU0ZUAUOrY-XDORunuHmxME
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                this.f$0.lambda$showMessagesSheet$9$VoIPActivity(editor, cell2, field, view);
            }
        });
        linearLayout.addView(frameLayout);
        bottomSheet.setCustomView(linearLayout);
        bottomSheet.setBackgroundColor(-13948117);
        bottomSheet.show();
    }

    public /* synthetic */ void lambda$showMessagesSheet$4$VoIPActivity(DialogInterface dialog) {
        getWindow().setNavigationBarColor(0);
    }

    public /* synthetic */ void lambda$showMessagesSheet$6$VoIPActivity(BottomSheet sheet, final View v) {
        sheet.dismiss();
        if (VoIPService.getSharedInstance() != null) {
            VoIPService.getSharedInstance().declineIncomingCall(4, new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$VoIPActivity$EYHLbCvGPmI5O_oi_eRu_M2pIS4
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$null$5$VoIPActivity(v);
                }
            });
        }
    }

    public /* synthetic */ void lambda$null$5$VoIPActivity(View v) {
        sendTextMessage((String) v.getTag());
    }

    public /* synthetic */ void lambda$showMessagesSheet$7$VoIPActivity(final EditText field, BottomSheet sheet, View v) {
        if (field.length() == 0) {
            return;
        }
        sheet.dismiss();
        if (VoIPService.getSharedInstance() != null) {
            VoIPService.getSharedInstance().declineIncomingCall(4, new Runnable() { // from class: im.uwrkaxlmjj.ui.VoIPActivity.29
                @Override // java.lang.Runnable
                public void run() {
                    VoIPActivity.this.sendTextMessage(field.getText().toString());
                }
            });
        }
    }

    public /* synthetic */ void lambda$showMessagesSheet$8$VoIPActivity(FrameLayout editor, BottomSheet.BottomSheetCell cell, EditText field, View v) {
        editor.setVisibility(8);
        cell.setVisibility(0);
        field.setText("");
        InputMethodManager imm = (InputMethodManager) getSystemService("input_method");
        imm.hideSoftInputFromWindow(field.getWindowToken(), 0);
    }

    public /* synthetic */ void lambda$showMessagesSheet$9$VoIPActivity(FrameLayout editor, BottomSheet.BottomSheetCell cell, EditText field, View v) {
        editor.setVisibility(0);
        cell.setVisibility(4);
        field.requestFocus();
        InputMethodManager imm = (InputMethodManager) getSystemService("input_method");
        imm.showSoftInput(field, 0);
    }

    private class TextAlphaSpan extends CharacterStyle {
        private int alpha = 0;

        public TextAlphaSpan() {
        }

        public int getAlpha() {
            return this.alpha;
        }

        public void setAlpha(int alpha) {
            this.alpha = alpha;
            VoIPActivity.this.stateText.invalidate();
            VoIPActivity.this.stateText2.invalidate();
        }

        @Override // android.text.style.CharacterStyle
        public void updateDrawState(TextPaint tp) {
            tp.setAlpha(this.alpha);
        }
    }

    private class SignalBarsDrawable extends Drawable {
        private int[] barHeights;
        private int offsetStart;
        private Paint paint;
        private RectF rect;

        private SignalBarsDrawable() {
            this.barHeights = new int[]{AndroidUtilities.dp(3.0f), AndroidUtilities.dp(6.0f), AndroidUtilities.dp(9.0f), AndroidUtilities.dp(12.0f)};
            this.paint = new Paint(1);
            this.rect = new RectF();
            this.offsetStart = 6;
        }

        @Override // android.graphics.drawable.Drawable
        public void draw(Canvas canvas) {
            if (VoIPActivity.this.callState != 3 && VoIPActivity.this.callState != 5) {
                return;
            }
            this.paint.setColor(-1);
            int x = getBounds().left + AndroidUtilities.dp(LocaleController.isRTL ? 0.0f : this.offsetStart);
            int y = getBounds().top;
            for (int i = 0; i < 4; i++) {
                this.paint.setAlpha(i + 1 <= VoIPActivity.this.signalBarsCount ? 242 : 102);
                this.rect.set(AndroidUtilities.dp(i * 4) + x, (getIntrinsicHeight() + y) - this.barHeights[i], (AndroidUtilities.dp(4.0f) * i) + x + AndroidUtilities.dp(3.0f), getIntrinsicHeight() + y);
                canvas.drawRoundRect(this.rect, AndroidUtilities.dp(0.3f), AndroidUtilities.dp(0.3f), this.paint);
            }
        }

        @Override // android.graphics.drawable.Drawable
        public void setAlpha(int alpha) {
        }

        @Override // android.graphics.drawable.Drawable
        public void setColorFilter(ColorFilter colorFilter) {
        }

        @Override // android.graphics.drawable.Drawable
        public int getIntrinsicWidth() {
            return AndroidUtilities.dp(this.offsetStart + 15);
        }

        @Override // android.graphics.drawable.Drawable
        public int getIntrinsicHeight() {
            return AndroidUtilities.dp(12.0f);
        }

        @Override // android.graphics.drawable.Drawable
        public int getOpacity() {
            return -3;
        }
    }
}
