package im.uwrkaxlmjj.ui.hui.visualcall;

import android.content.DialogInterface;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.res.Resources;
import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.graphics.Color;
import android.graphics.drawable.BitmapDrawable;
import android.media.SoundPool;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.SystemClock;
import android.text.TextUtils;
import android.view.SurfaceView;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Chronometer;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.RelativeLayout;
import android.widget.TextView;
import android.widget.Toast;
import androidx.recyclerview.widget.RecyclerView;
import butterknife.BindView;
import butterknife.ButterKnife;
import butterknife.OnClick;
import com.blankj.utilcode.constant.TimeConstants;
import com.ding.rtc.DingRtcEngine;
import com.ding.rtc.DingRtcEngineEventListener;
import com.google.android.exoplayer2.text.ttml.TtmlNode;
import com.google.android.exoplayer2.trackselection.AdaptiveTrackSelection;
import com.google.android.exoplayer2.upstream.DefaultLoadErrorHandlingPolicy;
import com.king.zxing.util.LogUtils;
import com.socks.library.KLog;
import ezy.assist.compat.SettingsCompat;
import im.uwrkaxlmjj.messenger.AccountInstance;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.ApplicationLoader;
import im.uwrkaxlmjj.messenger.ImageLocation;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.messenger.MessagesController;
import im.uwrkaxlmjj.messenger.NotificationCenter;
import im.uwrkaxlmjj.messenger.UserConfig;
import im.uwrkaxlmjj.messenger.Utilities;
import im.uwrkaxlmjj.tgnet.ConnectionsManager;
import im.uwrkaxlmjj.tgnet.TLObject;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.tgnet.TLRPCCall;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.components.AvatarDrawable;
import im.uwrkaxlmjj.ui.components.BackupImageView;
import im.uwrkaxlmjj.ui.components.ColorTextView;
import im.uwrkaxlmjj.ui.hui.visualcall.AVideoCallInterface;
import im.uwrkaxlmjj.ui.hui.visualcall.CallNetWorkReceiver;
import im.uwrkaxlmjj.ui.hviews.DragFrameLayout;
import im.uwrkaxlmjj.ui.hviews.dialogs.XDialog;
import im.uwrkaxlmjj.ui.hviews.helper.MryDeviceHelper;
import java.util.ArrayList;
import java.util.Timer;
import java.util.TimerTask;
import mpEIGo.juqQQs.esbSDO.R;
import org.json.JSONException;
import org.json.JSONObject;
import org.webrtc.alirtcInterface.ALI_RTC_INTERFACE;

/* JADX INFO: loaded from: classes5.dex */
public class VisualCallReceiveActivity extends BaseCallActivity implements NotificationCenter.NotificationCenterDelegate {
    private CallNetWorkReceiver callNetWorkReceiver;

    @BindView(R.attr.chart_content_userlist)
    RecyclerView chartContentUserlist;

    @BindView(R.attr.chart_video_container)
    DragFrameLayout chartVideoContainer;

    @BindView(R.attr.chr_visualcall_time)
    Chronometer chrVisualcallTime;
    private DynamicPoint dynamicPoint;

    @BindView(R.attr.img_operate_a)
    ImageView imgOperateA;

    @BindView(R.attr.img_operate_b)
    ImageView imgOperateB;

    @BindView(R.attr.img_operate_c)
    ImageView imgOperateC;

    @BindView(R.attr.img_pre_receive)
    ImageView imgPreReceive;

    @BindView(R.attr.img_user_head)
    BackupImageView imgUserHead;

    @BindView(R.attr.img_video_user_head)
    BackupImageView imgVideoUserHead;

    @BindView(R.attr.img_visualcall)
    ImageView imgVisualcall;

    @BindView(R.attr.iv_pre_refuse)
    ImageView ivPreRefuse;

    @BindView(R.attr.lin_operate_a)
    LinearLayout linOperateA;

    @BindView(R.attr.lin_operate_b)
    LinearLayout linOperateB;

    @BindView(R.attr.lin_operate_c)
    LinearLayout linOperateC;

    @BindView(R.attr.lin_pre_receive)
    LinearLayout linPreReceive;

    @BindView(R.attr.lin_pre_refuse)
    LinearLayout linPreRefuse;

    @BindView(R.attr.ll_big_remote_view)
    LinearLayout llBigRemoteView;

    @BindView(R.attr.ll_big_window)
    LinearLayout llBigWindow;

    @BindView(R.attr.ll_small_remote_view)
    LinearLayout llSmallRemoteView;
    TLRPC.User mUser;
    private long mlTipShow;

    @BindView(R.attr.rel_video_user)
    RelativeLayout relVideoUser;

    @BindView(R.attr.rel_visual_call_a)
    LinearLayout relVisualCallA;

    @BindView(R.attr.rel_visual_call_b)
    RelativeLayout relVisualCallB;

    @BindView(R.attr.rel_voice_user)
    RelativeLayout relVoiceUser;

    @BindView(R.attr.root_view)
    RelativeLayout rootView;
    private SurfaceView sfLocalView;
    private SurfaceView sfSmallView;
    private SoundPool soundPool;
    private int spConnectingId;

    @BindView(R.attr.txt_call_name)
    TextView txtCallName;

    @BindView(R.attr.txt_call_status)
    ColorTextView txtCallStatus;

    @BindView(R.attr.txt_mask)
    TextView txtMask;

    @BindView(R.attr.txt_operate_a)
    ColorTextView txtOperateA;

    @BindView(R.attr.txt_operate_b)
    ColorTextView txtOperateB;

    @BindView(R.attr.txt_operate_c)
    ColorTextView txtOperateC;

    @BindView(R.attr.txt_pre_change_to_voice)
    ColorTextView txtPreChangeToVoice;

    @BindView(R.attr.txt_tip)
    TextView txtTip;

    @BindView(R.attr.txt_video_name)
    TextView txtVideoName;

    @BindView(R.attr.txt_video_status)
    ColorTextView txtVideoStatus;

    @BindView(R.attr.txt_visualcall_status)
    ColorTextView txtVisualcallStatus;
    private long mlStart = 0;
    private long mlLastClickTime = 0;
    private byte mbytIsForeground = 1;
    private byte mbytExit = 0;
    private byte mbytNoOp = 0;
    private Timer timer = new Timer();
    private TimerTask timerTask = null;
    private boolean mblnResetNoOp = false;
    private byte RESPONSE_REFUSE = -1;
    private byte REQUEST_NO_ANSWER = -4;
    private byte REQUEST_NETWORK_NO_ANSWER = -6;
    private byte mbytLastClickIndex = -1;
    private boolean mblnUnProcessChooseVoiceTip = false;
    private byte mbytFPacketRecCount = 0;

    @Override // im.uwrkaxlmjj.ui.hui.visualcall.BaseCallActivity, android.app.Activity
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        ApplicationLoader.mbytAVideoCallBusy = (byte) 1;
        setFullScreen();
        setContentView(R.layout.activity_visual_call_receive);
        if (getIntent().getIntExtra("from", 0) == 0) {
            RingUtils.playRingBySoundPool(this);
        }
        RingUtils.stopPlayVibrator();
        ButterKnife.bind(this);
        getWindow().addFlags(128);
        fillAliRtcUserInfo();
        regNotification();
        initEventListener();
        this.dynamicPoint = new DynamicPoint();
        this.chartVideoContainer.setY(AndroidUtilities.statusBarHeight);
        initRTCEngineAndStartPreview();
        sendKeepLivePacket(this.mChannel);
        this.txtTip.setBackground(Theme.createRoundRectDrawable(AndroidUtilities.dp(8.0f), Color.parseColor("#CB2D2D2D")));
        this.mUser = MessagesController.getInstance(UserConfig.selectedAccount).getUser(Integer.valueOf(getIntent().getIntExtra("admin_id", 0)));
        boolean blnVideo = getIntent().getBooleanExtra("video", false);
        this.callStyle = blnVideo ? 2 : 1;
        setAVideoUI();
        this.mSmallWindow = this.chartVideoContainer;
        this.mBigWindow = this.llBigWindow;
        this.mChronometer = this.chrVisualcallTime;
        this.chrVisualcallTime.setOnChronometerTickListener(new Chronometer.OnChronometerTickListener() { // from class: im.uwrkaxlmjj.ui.hui.visualcall.VisualCallReceiveActivity.1
            @Override // android.widget.Chronometer.OnChronometerTickListener
            public void onChronometerTick(Chronometer chronometer) {
                StringBuilder sb;
                String ss;
                long time = SystemClock.elapsedRealtime() - chronometer.getBase();
                int h = (int) (time / 3600000);
                int m = ((int) (time - ((long) (h * TimeConstants.HOUR)))) / 60000;
                int s = ((int) ((time - ((long) (TimeConstants.HOUR * h))) - ((long) (60000 * m)))) / 1000;
                if (h > 0) {
                    m += h * 60;
                }
                if (m < 10) {
                    sb = new StringBuilder();
                    sb.append("0");
                    sb.append(m);
                } else {
                    sb = new StringBuilder();
                    sb.append(m);
                    sb.append("");
                }
                String mm = sb.toString();
                if (s < 10) {
                    ss = "0" + s;
                } else {
                    ss = s + "";
                }
                String timeFormat = mm + LogUtils.COLON + ss;
                chronometer.setText(timeFormat);
            }
        });
        regNetWorkReceiver();
        this.chartVideoContainer.setVisibility(8);
        if (this.callStyle == 1) {
            this.txtPreChangeToVoice.setVisibility(8);
        }
        this.linOperateA.postDelayed(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.visualcall.-$$Lambda$VisualCallReceiveActivity$vwnOC7ZmiqK7cjlM5DsDF3uH7Bw
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$onCreate$0$VisualCallReceiveActivity();
            }
        }, 35000L);
        ConnectionsManager.getInstance(UserConfig.selectedAccount).setAppPaused(false, false);
    }

    public /* synthetic */ void lambda$onCreate$0$VisualCallReceiveActivity() {
        if (this.mbytNoOp == 0 && !this.mblnResetNoOp) {
            ProcessDiscardMessage(1, null);
        }
    }

    protected void regNetWorkReceiver() {
        IntentFilter filter = new IntentFilter();
        filter.addAction("android.net.conn.CONNECTIVITY_CHANGE");
        CallNetWorkReceiver callNetWorkReceiver = new CallNetWorkReceiver();
        this.callNetWorkReceiver = callNetWorkReceiver;
        registerReceiver(callNetWorkReceiver, filter);
        this.callNetWorkReceiver.setCallBack(new CallNetWorkReceiver.NetWorkStateCallBack() { // from class: im.uwrkaxlmjj.ui.hui.visualcall.VisualCallReceiveActivity.2
            @Override // im.uwrkaxlmjj.ui.hui.visualcall.CallNetWorkReceiver.NetWorkStateCallBack
            public void onNetWorkConnected() {
                VisualCallReceiveActivity visualCallReceiveActivity = VisualCallReceiveActivity.this;
                visualCallReceiveActivity.sendKeepLivePacket(visualCallReceiveActivity.mChannel);
            }

            @Override // im.uwrkaxlmjj.ui.hui.visualcall.CallNetWorkReceiver.NetWorkStateCallBack
            public void onNetWorkDisconnected() {
            }
        });
    }

    private void setBlurBitmap() {
        this.txtMask.setAlpha(0.8f);
        Bitmap bitmap = BitmapFactory.decodeResource(getResources(), R.drawable.visualcall_bg);
        Bitmap b1 = Utilities.blurWallpaper(bitmap);
        this.txtMask.setBackground(new BitmapDrawable((Resources) null, b1));
    }

    private void initRing() {
        SoundPool soundPool = new SoundPool(1, 0, 0);
        this.soundPool = soundPool;
        this.spConnectingId = soundPool.load(this, R.raw.visual_call_receive, 1);
        this.soundPool.setOnLoadCompleteListener(new SoundPool.OnLoadCompleteListener() { // from class: im.uwrkaxlmjj.ui.hui.visualcall.-$$Lambda$VisualCallReceiveActivity$kwKoYV6-jw8m0XDD0odYpjImqR4
            @Override // android.media.SoundPool.OnLoadCompleteListener
            public final void onLoadComplete(SoundPool soundPool2, int i, int i2) {
                this.f$0.lambda$initRing$1$VisualCallReceiveActivity(soundPool2, i, i2);
            }
        });
    }

    public /* synthetic */ void lambda$initRing$1$VisualCallReceiveActivity(SoundPool soundPool, int sampleId, int status) {
        soundPool.play(this.spConnectingId, 1.0f, 1.0f, 0, -1, 1.0f);
    }

    public void stopRinging() {
        RingUtils.stopSoundPoolRing();
    }

    private void setAVideoUI() {
        String strName = "";
        TLRPC.User user = this.mUser;
        if (user != null) {
            strName = user.first_name;
        }
        AvatarDrawable avatarDrawable = new AvatarDrawable();
        avatarDrawable.setInfo(this.mUser);
        if (this.callStyle == 2) {
            this.imgPreReceive.setBackgroundResource(R.drawable.visualcall_video_receive);
            this.relVoiceUser.setVisibility(8);
            this.relVideoUser.setVisibility(0);
            SurfaceView surfaceView = this.sfLocalView;
            if (surfaceView != null) {
                surfaceView.setVisibility(0);
            }
            this.txtVideoName.setText(strName);
            setBlurBitmap();
            this.txtMask.setVisibility(0);
            this.imgVideoUserHead.setRoundRadius(AndroidUtilities.dp(70.0f));
            this.imgVideoUserHead.setImage(ImageLocation.getForUser(this.mUser, false), "50_50", avatarDrawable, this.mUser);
            this.dynamicPoint.animForWaitting(LocaleController.getString("visual_call_invate", R.string.visual_call_invate), this.txtVideoStatus);
            if (Build.VERSION.SDK_INT >= 21 && !AndroidUtilities.checkCamera(this)) {
                this.txtTip.setVisibility(0);
                setTipPos();
                this.txtTip.setText(LocaleController.getString("visual_call_change_to_voice", R.string.visual_call_change_to_voice));
                return;
            }
            return;
        }
        this.imgPreReceive.setBackgroundResource(R.drawable.visualcall_receive_common);
        this.relVoiceUser.setVisibility(0);
        this.relVideoUser.setVisibility(8);
        SurfaceView surfaceView2 = this.sfLocalView;
        if (surfaceView2 != null) {
            surfaceView2.setVisibility(8);
        }
        this.txtCallName.setText(strName);
        this.imgUserHead.setRoundRadius(AndroidUtilities.dp(70.0f));
        this.imgUserHead.setImage(ImageLocation.getForUser(this.mUser, false), "50_50", avatarDrawable, this.mUser);
        if (this.VisualCallType != 3) {
            if (this.mbytNoOp == 0) {
                this.dynamicPoint.animForWaitting(LocaleController.getString("visual_call_invate_voice", R.string.visual_call_invate_voice), this.txtCallStatus);
            } else {
                this.dynamicPoint.animForWaitting(LocaleController.getString(R.string.visual_call_calling), this.txtCallStatus);
                this.imgPreReceive.setBackgroundResource(R.drawable.visualcall_receive);
            }
        }
    }

    /* JADX INFO: renamed from: im.uwrkaxlmjj.ui.hui.visualcall.VisualCallReceiveActivity$3, reason: invalid class name */
    class AnonymousClass3 extends TimerTask {
        final /* synthetic */ String val$strId;

        AnonymousClass3(String str) {
            this.val$strId = str;
        }

        @Override // java.util.TimerTask, java.lang.Runnable
        public void run() {
            final String str = this.val$strId;
            ThreadUtils.runOnUiThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.visualcall.-$$Lambda$VisualCallReceiveActivity$3$7Um8s8PqWF1EH6R8SAgVKSjeh74
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$run$0$VisualCallReceiveActivity$3(str);
                }
            });
        }

        public /* synthetic */ void lambda$run$0$VisualCallReceiveActivity$3(String strId) {
            AVideoCallInterface.sendJumpPacket(strId, new AVideoCallInterface.AVideoRequestCallBack() { // from class: im.uwrkaxlmjj.ui.hui.visualcall.VisualCallReceiveActivity.3.1
                @Override // im.uwrkaxlmjj.ui.hui.visualcall.AVideoCallInterface.AVideoRequestCallBack
                public void onError(TLRPC.TL_error error) {
                }

                @Override // im.uwrkaxlmjj.ui.hui.visualcall.AVideoCallInterface.AVideoRequestCallBack
                public void onSuccess(TLObject object) {
                    if (object instanceof TLRPCCall.TL_MeetModel) {
                        TLRPCCall.TL_MeetModel model = (TLRPCCall.TL_MeetModel) object;
                        if (model.id.equals(VisualCallReceiveActivity.this.mChannel) && !model.video && VisualCallReceiveActivity.this.callStyle == 2) {
                            VisualCallReceiveActivity.this.callStyle = 1;
                            VisualCallReceiveActivity.this.changeToVoice(false);
                        }
                    }
                }
            });
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void sendKeepLivePacket(String strId) {
        if (this.timerTask == null) {
            AnonymousClass3 anonymousClass3 = new AnonymousClass3(strId);
            this.timerTask = anonymousClass3;
            this.timer.schedule(anonymousClass3, 1000L, 14000L);
        }
    }

    private void fillAliRtcUserInfo() {
        this.mRtcAuthInfo.data.appid = getIntent().getStringExtra("app_id");
        this.mRtcAuthInfo.data.token = getIntent().getStringExtra("token");
        this.mRtcAuthInfo.data.userid = String.valueOf(AccountInstance.getInstance(UserConfig.selectedAccount).getUserConfig().getCurrentUser().id);
        ArrayList<String> arrgslb = getIntent().getStringArrayListExtra("gslb");
        if (arrgslb != null) {
            String[] strArr = new String[arrgslb.size()];
            int i = 0;
            for (String strServer : arrgslb) {
                strArr[i] = strServer;
                i++;
            }
            this.mRtcAuthInfo.data.gslb = strArr;
        }
        String strJson = getIntent().getStringExtra("json");
        if (strJson != null) {
            try {
                JSONObject jsonObject = new JSONObject(strJson);
                this.mRtcAuthInfo.data.timestamp = jsonObject.getLong("time_stamp");
                this.mRtcAuthInfo.data.setNonce(jsonObject.getString("nonce"));
            } catch (JSONException e) {
                e.printStackTrace();
            }
        }
        this.mChannel = getIntent().getStringExtra(TtmlNode.ATTR_ID);
    }

    @OnClick({R.attr.img_operate_a, R.attr.img_operate_b, R.attr.img_operate_c, R.attr.img_pre_receive, R.attr.iv_pre_refuse, R.attr.img_visualcall, R.attr.chart_video_container, R.attr.ll_big_window, R.attr.txt_pre_change_to_voice})
    public void onViewClicked(View view) {
        switch (view.getId()) {
            case R.attr.chart_video_container /* 2131296459 */:
                if (!this.chartVideoContainer.isDrag()) {
                    changeLocalPreview(null);
                }
                break;
            case R.attr.img_operate_a /* 2131296681 */:
                if (this.imgOperateA.isEnabled() && this.mAliRtcEngine != null) {
                    if (this.callStyle == 2) {
                        this.callStyle = 1;
                        AVideoCallInterface.ChangeToVoiceCall(this.mChannel, this.callStyle == 2);
                        if (this.mAliRtcEngine.isLocalVideoStreamPublished()) {
                            KLog.d("--------关闭视频流");
                            this.mAliRtcEngine.publishLocalVideoStream(false);
                        }
                        changeToVoice(true);
                    } else if (this.mbytLastClickIndex != 0 || System.currentTimeMillis() - this.mlLastClickTime > 500) {
                        this.mlLastClickTime = System.currentTimeMillis();
                        this.mIsAudioCapture = !this.mIsAudioCapture;
                        if (this.mIsAudioCapture) {
                            this.mAliRtcEngine.publishLocalAudioStream(false);
                            this.imgOperateA.setBackgroundResource(R.drawable.visualcall_no_voice);
                        } else {
                            this.imgOperateA.setBackgroundResource(R.drawable.visualcall_no_voice_selected);
                            this.mAliRtcEngine.publishLocalAudioStream(true);
                        }
                    }
                }
                this.mbytLastClickIndex = (byte) 0;
                break;
            case R.attr.img_operate_b /* 2131296682 */:
                if (this.imgOperateB.isEnabled()) {
                    this.mChannel = "666";
                    cancelCallingState();
                    this.chrVisualcallTime.stop();
                    this.imgOperateB.setBackgroundResource(R.drawable.visualcall_cancel);
                    this.imgOperateB.setEnabled(false);
                    this.imgOperateA.setEnabled(false);
                    AVideoCallInterface.DiscardAVideoCall(getIntent().getStringExtra(TtmlNode.ATTR_ID), ((int) (System.currentTimeMillis() - this.mlStart)) / 1000, this.callStyle == 2);
                    this.txtTip.setText(LocaleController.getString("visual_call_over", R.string.visual_call_over));
                    this.txtTip.setVisibility(0);
                    setTipPos();
                    this.txtTip.postDelayed(new $$Lambda$XBP5wqdfkxd6BRIGp0CRLqrqCB8(this), AdaptiveTrackSelection.DEFAULT_MIN_TIME_BETWEEN_BUFFER_REEVALUTATION_MS);
                }
                break;
            case R.attr.img_operate_c /* 2131296683 */:
                if (this.VisualCallType == 3 && this.mAliRtcEngine != null && (this.mbytLastClickIndex != 1 || System.currentTimeMillis() - this.mlLastClickTime > 500)) {
                    this.mlLastClickTime = System.currentTimeMillis();
                    if (this.callStyle == 2) {
                        if (this.mAliRtcEngine.switchCamera() == 0) {
                            KLog.d("----------设置成功");
                            if (this.mAliRtcEngine.getCurrentCameraDirection() == DingRtcEngine.DingRtcCameraDirection.CAMERA_REAR) {
                                this.imgOperateC.setBackgroundResource(R.drawable.visualcall_camera_changed);
                            } else if (this.mAliRtcEngine.getCurrentCameraDirection() == DingRtcEngine.DingRtcCameraDirection.CAMERA_FRONT) {
                                this.imgOperateC.setBackgroundResource(R.drawable.visualcall_camera);
                            }
                        }
                    } else if (this.mAliRtcEngine.isSpeakerphoneEnabled()) {
                        this.imgOperateC.setBackgroundResource(R.drawable.visualcall_hands_free);
                        this.mAliRtcEngine.enableSpeakerphone(false);
                    } else {
                        this.imgOperateC.setBackgroundResource(R.drawable.visual_hands_free_selected);
                        this.mAliRtcEngine.enableSpeakerphone(true);
                    }
                }
                this.mbytLastClickIndex = (byte) 1;
                break;
            case R.attr.img_pre_receive /* 2131296685 */:
                this.mbytNoOp = (byte) 1;
                if (this.imgPreReceive.isEnabled() && this.mGrantPermission) {
                    this.imgPreReceive.setEnabled(false);
                    stopRinging();
                    if (this.callStyle == 2) {
                        this.dynamicPoint.animForWaitting(LocaleController.getString("visual_call_calling", R.string.visual_call_calling), this.txtVideoStatus);
                        this.imgPreReceive.setBackgroundResource(R.drawable.visualcall_video_receive_common);
                    } else {
                        this.dynamicPoint.animForWaitting(LocaleController.getString("visual_call_calling", R.string.visual_call_calling), this.txtCallStatus);
                        this.imgPreReceive.setBackgroundResource(R.drawable.visualcall_receive);
                    }
                    openJoinChannelBeforeNeedParams();
                    if (this.mGrantPermission) {
                        new Thread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.visualcall.-$$Lambda$JhtmO6txloKXtcnm3CQlP7MXrmQ
                            @Override // java.lang.Runnable
                            public final void run() {
                                this.f$0.joinChannel();
                            }
                        }).start();
                    } else {
                        setUpSplash();
                    }
                    AVideoCallInterface.AcceptAVideoCall(getIntent().getStringExtra(TtmlNode.ATTR_ID), new AVideoCallInterface.AVideoRequestCallBack() { // from class: im.uwrkaxlmjj.ui.hui.visualcall.VisualCallReceiveActivity.4
                        @Override // im.uwrkaxlmjj.ui.hui.visualcall.AVideoCallInterface.AVideoRequestCallBack
                        public void onError(TLRPC.TL_error error) {
                            if (error.text.equals("PEER_DISCARD")) {
                                VisualCallReceiveActivity.this.ProcessDiscardMessage(1, null);
                            }
                        }

                        @Override // im.uwrkaxlmjj.ui.hui.visualcall.AVideoCallInterface.AVideoRequestCallBack
                        public void onSuccess(TLObject object) {
                        }
                    });
                    this.relVideoUser.postDelayed(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.visualcall.-$$Lambda$VisualCallReceiveActivity$xP9Fur-5qZYPnQaFSberKNqY76o
                        @Override // java.lang.Runnable
                        public final void run() {
                            this.f$0.lambda$onViewClicked$2$VisualCallReceiveActivity();
                        }
                    }, DefaultLoadErrorHandlingPolicy.DEFAULT_TRACK_BLACKLIST_MS);
                    break;
                }
                break;
            case R.attr.img_visualcall /* 2131296693 */:
                if (this.imgVisualcall.isEnabled()) {
                    if (SettingsCompat.canDrawOverlays(this)) {
                        ApplicationLoader.mbytAVideoCallBusy = (byte) 3;
                        if (this.callStyle == 2) {
                            this.chartVideoContainer.setVisibility(8);
                        }
                        startVideoService();
                    } else if (MryDeviceHelper.isOppo()) {
                        showPermissionErrorAlert(LocaleController.getString("PermissionPopWindowOppo", R.string.PermissionPopWindowOppo));
                    } else {
                        showPermissionErrorAlert(LocaleController.getString("PermissionPopWindow", R.string.PermissionPopWindow));
                    }
                }
                break;
            case R.attr.iv_pre_refuse /* 2131296831 */:
                this.mbytNoOp = (byte) 1;
                if (this.ivPreRefuse.isEnabled()) {
                    KLog.d("call id === " + getIntent().getStringExtra(TtmlNode.ATTR_ID));
                    this.mChannel = "666";
                    stopRinging();
                    cancelCallingState();
                    this.ivPreRefuse.setBackgroundResource(R.drawable.visualcall_cancel);
                    this.ivPreRefuse.setEnabled(false);
                    this.txtPreChangeToVoice.setEnabled(false);
                    AVideoCallInterface.DiscardAVideoCall(getIntent().getStringExtra(TtmlNode.ATTR_ID), this.RESPONSE_REFUSE, this.callStyle == 2);
                    this.txtTip.setText(LocaleController.getString("visual_call_refused_over", R.string.visual_call_refused_over));
                    this.txtTip.setVisibility(0);
                    setTipPos();
                    this.txtTip.postDelayed(new $$Lambda$XBP5wqdfkxd6BRIGp0CRLqrqCB8(this), AdaptiveTrackSelection.DEFAULT_MIN_TIME_BETWEEN_BUFFER_REEVALUTATION_MS);
                }
                break;
            case R.attr.ll_big_window /* 2131296927 */:
                if (this.callStyle == 2 && this.VisualCallType == 3) {
                    if (this.imgVisualcall.getVisibility() == 8) {
                        this.imgVisualcall.setVisibility(0);
                        this.linOperateA.setVisibility(0);
                        this.linOperateB.setVisibility(0);
                        this.linOperateC.setVisibility(0);
                        this.chrVisualcallTime.setVisibility(0);
                    } else {
                        this.imgVisualcall.setVisibility(8);
                        this.linOperateA.setVisibility(8);
                        this.linOperateB.setVisibility(8);
                        this.linOperateC.setVisibility(8);
                        this.chrVisualcallTime.setVisibility(8);
                    }
                    break;
                }
                break;
            case R.attr.txt_pre_change_to_voice /* 2131297897 */:
                if (this.txtPreChangeToVoice.isEnabled() && this.mAliRtcEngine != null) {
                    this.callStyle = 1;
                    AVideoCallInterface.ChangeToVoiceCall(this.mChannel, this.callStyle == 2);
                    if (this.mAliRtcEngine.isLocalVideoStreamPublished()) {
                        KLog.d("--------关闭视频流");
                        this.mAliRtcEngine.publishLocalVideoStream(false);
                    }
                    changeToVoice(true);
                    this.mblnResetNoOp = true;
                    this.linOperateA.postDelayed(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.visualcall.-$$Lambda$VisualCallReceiveActivity$gXLRmDG4e0QjePyq63vzw9WOpDI
                        @Override // java.lang.Runnable
                        public final void run() {
                            this.f$0.lambda$onViewClicked$3$VisualCallReceiveActivity();
                        }
                    }, 35000L);
                    break;
                }
                break;
        }
    }

    public /* synthetic */ void lambda$onViewClicked$2$VisualCallReceiveActivity() {
        if (this.VisualCallType != 3) {
            AVideoCallInterface.DiscardAVideoCall(getIntent().getStringExtra(TtmlNode.ATTR_ID), this.REQUEST_NETWORK_NO_ANSWER, this.callStyle == 2);
            this.txtTip.setVisibility(0);
            this.txtTip.setText(LocaleController.getString("visual_call_retry", R.string.visual_call_retry));
            setTipPos();
            cancelCallingState();
            this.txtTip.postDelayed(new $$Lambda$XBP5wqdfkxd6BRIGp0CRLqrqCB8(this), AdaptiveTrackSelection.DEFAULT_MIN_TIME_BETWEEN_BUFFER_REEVALUTATION_MS);
        }
    }

    public /* synthetic */ void lambda$onViewClicked$3$VisualCallReceiveActivity() {
        if (this.mbytNoOp == 0) {
            ProcessDiscardMessage(1, null);
        }
    }

    private void enterCallingMode() {
        this.relVisualCallB.setVisibility(8);
        this.relVisualCallA.setVisibility(0);
        if (this.callStyle == 2) {
            this.txtPreChangeToVoice.setVisibility(8);
            this.linOperateA.setVisibility(0);
            this.imgOperateA.setBackgroundResource(R.drawable.visualcall_to_voice);
            this.txtOperateA.setText(LocaleController.getString("Str_visualcall_to_voice", R.string.Str_visualcall_to_voice));
            this.imgOperateC.setBackgroundResource(R.drawable.visualcall_camera);
            this.txtOperateC.setText(LocaleController.getString("Str_visualcall_change_camera", R.string.Str_visualcall_change_camera));
            return;
        }
        if (this.callStyle == 1) {
            this.txtCallStatus.setVisibility(8);
        }
    }

    @Override // im.uwrkaxlmjj.messenger.NotificationCenter.NotificationCenterDelegate
    public void didReceivedNotification(int id, int account, Object... args) {
        if (id == NotificationCenter.receivedAVideoCallReady) {
            TLRPCCall.TL_UpdateMeetCall meetCall = (TLRPCCall.TL_UpdateMeetCall) args[0];
            if (meetCall != null && meetCall.id.equals(this.mChannel)) {
                this.mblnOtherIsPc = meetCall.isPc;
                return;
            }
            return;
        }
        if (id == NotificationCenter.reecivedAVideoDiscarded) {
            TLRPCCall.TL_UpdateMeetCallDiscarded discarded = (TLRPCCall.TL_UpdateMeetCallDiscarded) args[0];
            if (discarded != null && discarded.id.equals(this.mChannel)) {
                this.imgVisualcall.setEnabled(false);
                if (discarded.duration != -1) {
                    if (discarded.duration != 0) {
                        ProcessDiscardMessage(0, null);
                        return;
                    } else {
                        ProcessDiscardMessage(0, LocaleController.getString(R.string.visual_call_received_in_other));
                        return;
                    }
                }
                stopRinging();
                cancelCallingState();
                this.ivPreRefuse.setBackgroundResource(R.drawable.visualcall_cancel);
                this.ivPreRefuse.setEnabled(false);
                AVideoCallInterface.DiscardAVideoCall(getIntent().getStringExtra(TtmlNode.ATTR_ID), this.RESPONSE_REFUSE, this.callStyle == 2);
                this.txtTip.setText(LocaleController.getString("visual_call_refused_over", R.string.visual_call_refused_over));
                this.txtTip.setVisibility(0);
                setTipPos();
                this.txtTip.postDelayed(new $$Lambda$XBP5wqdfkxd6BRIGp0CRLqrqCB8(this), AdaptiveTrackSelection.DEFAULT_MIN_TIME_BETWEEN_BUFFER_REEVALUTATION_MS);
                return;
            }
            return;
        }
        if (id == NotificationCenter.receivedAVideoCallChangeVoice) {
            this.callStyle = 1;
            changeToVoice(false);
            if (this.mbytNoOp == 0) {
                this.mblnResetNoOp = true;
                this.linOperateA.postDelayed(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.visualcall.-$$Lambda$VisualCallReceiveActivity$IInHLlhgQ8RUu0r6zcTvYnFJRVo
                    @Override // java.lang.Runnable
                    public final void run() {
                        this.f$0.lambda$didReceivedNotification$4$VisualCallReceiveActivity();
                    }
                }, 35000L);
            }
        }
    }

    public /* synthetic */ void lambda$didReceivedNotification$4$VisualCallReceiveActivity() {
        if (this.mbytNoOp == 0) {
            ProcessDiscardMessage(1, null);
        }
    }

    protected void ProcessDiscardMessage(int iFlag, String strTip) {
        if (iFlag == 1) {
            AVideoCallInterface.DiscardAVideoCall(getIntent().getStringExtra(TtmlNode.ATTR_ID), this.REQUEST_NO_ANSWER, this.callStyle == 2);
        }
        stopRinging();
        if (this.VisualCallType == 3) {
            this.txtTip.setText(LocaleController.getString("visual_call_other_side_discard", R.string.visual_call_other_side_discard));
            this.txtTip.setVisibility(0);
            this.chrVisualcallTime.stop();
            this.txtTip.postDelayed(new $$Lambda$XBP5wqdfkxd6BRIGp0CRLqrqCB8(this), AdaptiveTrackSelection.DEFAULT_MIN_TIME_BETWEEN_BUFFER_REEVALUTATION_MS);
        } else {
            this.txtTip.setText(strTip == null ? LocaleController.getString(R.string.visual_call_other_side_cancel) : strTip);
            this.txtTip.setVisibility(0);
            setTipPos();
            this.txtTip.postDelayed(new $$Lambda$XBP5wqdfkxd6BRIGp0CRLqrqCB8(this), AdaptiveTrackSelection.DEFAULT_MIN_TIME_BETWEEN_BUFFER_REEVALUTATION_MS);
        }
        cancelCallingState();
    }

    protected void removeRemoteUser(final String uid) {
        KLog.d("---------远端用户下线通知" + uid);
        runOnUiThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.visualcall.-$$Lambda$VisualCallReceiveActivity$8_X_eS1Ii6sK_ySEFOOnwRNi5go
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$removeRemoteUser$5$VisualCallReceiveActivity(uid);
            }
        });
    }

    public /* synthetic */ void lambda$removeRemoteUser$5$VisualCallReceiveActivity(String uid) {
        this.mUserListAdapter.removeData(uid, true);
        if (!this.mChannel.equals("666")) {
            stopRinging();
            if (this.VisualCallType == 3) {
                this.txtTip.setText(LocaleController.getString("visual_call_other_side_discard", R.string.visual_call_other_side_discard));
                this.txtTip.setVisibility(0);
                this.chrVisualcallTime.stop();
                this.txtTip.postDelayed(new $$Lambda$XBP5wqdfkxd6BRIGp0CRLqrqCB8(this), AdaptiveTrackSelection.DEFAULT_MIN_TIME_BETWEEN_BUFFER_REEVALUTATION_MS);
            } else {
                this.txtTip.setText(LocaleController.getString("visual_call_other_side_cancel", R.string.visual_call_other_side_cancel));
                this.txtTip.setVisibility(0);
                this.txtTip.postDelayed(new $$Lambda$XBP5wqdfkxd6BRIGp0CRLqrqCB8(this), AdaptiveTrackSelection.DEFAULT_MIN_TIME_BETWEEN_BUFFER_REEVALUTATION_MS);
            }
            cancelCallingState();
        }
    }

    private void regNotification() {
        NotificationCenter.getGlobalInstance().addObserver(this, NotificationCenter.receivedAVideoCallReady);
        NotificationCenter.getGlobalInstance().addObserver(this, NotificationCenter.reecivedAVideoDiscarded);
        NotificationCenter.getGlobalInstance().addObserver(this, NotificationCenter.receivedAVideoCallChangeVoice);
    }

    @Override // im.uwrkaxlmjj.ui.hui.visualcall.BaseCallActivity, android.app.Activity
    protected void onDestroy() {
        this.mbytNoOp = (byte) 1;
        NotificationCenter.getGlobalInstance().removeObserver(this, NotificationCenter.receivedAVideoCallReady);
        NotificationCenter.getGlobalInstance().removeObserver(this, NotificationCenter.reecivedAVideoDiscarded);
        NotificationCenter.getGlobalInstance().removeObserver(this, NotificationCenter.receivedAVideoCallChangeVoice);
        CallNetWorkReceiver callNetWorkReceiver = this.callNetWorkReceiver;
        if (callNetWorkReceiver != null) {
            unregisterReceiver(callNetWorkReceiver);
        }
        this.dynamicPoint.release();
        this.timer.cancel();
        this.timer.purge();
        TimerTask timerTask = this.timerTask;
        if (timerTask != null) {
            timerTask.cancel();
        }
        super.onDestroy();
    }

    @Override // im.uwrkaxlmjj.ui.hui.visualcall.BaseCallActivity
    protected void initLocalView() {
        this.aliVideoCanvasBig = new DingRtcEngine.DingRtcVideoCanvas();
        SurfaceView surfaceViewCreateRenderSurfaceView = this.mAliRtcEngine.createRenderSurfaceView(this);
        this.sfLocalView = surfaceViewCreateRenderSurfaceView;
        if (surfaceViewCreateRenderSurfaceView == null) {
            Toast.makeText(getApplicationContext(), "创建画布失败", 0).show();
        } else {
            surfaceViewCreateRenderSurfaceView.setZOrderMediaOverlay(true);
            this.aliVideoCanvasBig.view = this.sfLocalView;
        }
        this.aliVideoCanvasBig.renderMode = DingRtcEngine.DingRtcRenderMode.DingRtcRenderModeAuto;
        this.llBigWindow.addView(this.sfLocalView);
        this.aliVideoCanvasSmall = new DingRtcEngine.DingRtcVideoCanvas();
        SurfaceView surfaceViewCreateRenderSurfaceView2 = this.mAliRtcEngine.createRenderSurfaceView(this);
        this.sfSmallView = surfaceViewCreateRenderSurfaceView2;
        if (surfaceViewCreateRenderSurfaceView2 == null) {
            Toast.makeText(getApplicationContext(), "创建画布失败", 0).show();
        } else {
            surfaceViewCreateRenderSurfaceView2.setZOrderOnTop(true);
            this.aliVideoCanvasSmall.view = this.sfSmallView;
        }
        this.aliVideoCanvasSmall.renderMode = DingRtcEngine.DingRtcRenderMode.DingRtcRenderModeAuto;
        String largeViewUid = getIntent().getStringExtra("user_id");
        this.mAliRtcEngine.setRemoteViewConfig(this.aliVideoCanvasSmall, largeViewUid, DingRtcEngine.DingRtcVideoTrack.DingRtcVideoTrackCamera);
        this.chartVideoContainer.addView(this.sfSmallView);
        if (this.mAliRtcEngine != null) {
            this.mAliRtcEngine.setLocalViewConfig(this.aliVideoCanvasBig, DingRtcEngine.DingRtcVideoTrack.DingRtcVideoTrackCamera);
        }
    }

    @Override // im.uwrkaxlmjj.ui.hui.visualcall.BaseCallActivity
    protected void initView() {
    }

    @Override // im.uwrkaxlmjj.ui.hui.visualcall.BaseCallActivity
    protected void changeStatusView() {
        enterCallingMode();
    }

    @Override // android.app.Activity
    public void onRequestPermissionsResult(int requestCode, String[] permissions, int[] grantResults) {
        if (requestCode == 100) {
            PermissionUtils.requestPermissionsResult(this, requestCode, permissions, grantResults, this.mGrant);
        } else {
            super.onRequestPermissionsResult(requestCode, permissions, grantResults);
        }
    }

    @Override // android.app.Activity
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode == 100) {
            new Handler().postDelayed(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.visualcall.-$$Lambda$eu5daOkjweAG2dahGHK8qkmxtfU
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$setUpSplash$0$BaseCallActivity();
                }
            }, 500L);
        }
    }

    /* JADX INFO: renamed from: im.uwrkaxlmjj.ui.hui.visualcall.VisualCallReceiveActivity$5, reason: invalid class name */
    class AnonymousClass5 extends DingRtcEngineEventListener {
        AnonymousClass5() {
        }

        @Override // com.ding.rtc.DingRtcEngineEventListener
        public void onJoinChannelResult(int result, String channel, String userId, int elapsed) {
            KLog.d("++++++++++成功加入房间");
            VisualCallReceiveActivity.this.runOnUiThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.visualcall.-$$Lambda$VisualCallReceiveActivity$5$44p_KloAynI5jPukIOHfeBxy1BY
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$onJoinChannelResult$0$VisualCallReceiveActivity$5();
                }
            });
        }

        public /* synthetic */ void lambda$onJoinChannelResult$0$VisualCallReceiveActivity$5() {
            VisualCallReceiveActivity.this.mAliRtcEngine.publishLocalAudioStream(true);
        }

        @Override // com.ding.rtc.DingRtcEngineEventListener
        public void onNetworkQualityChanged(final String s, final DingRtcEngine.DingRtcNetworkQuality upQuality, final DingRtcEngine.DingRtcNetworkQuality downQuality) {
            VisualCallReceiveActivity.this.runOnUiThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.visualcall.-$$Lambda$VisualCallReceiveActivity$5$nGoCPFYUSwq1ifBdtPv4XDDAyS8
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$onNetworkQualityChanged$1$VisualCallReceiveActivity$5(upQuality, downQuality, s);
                }
            });
        }

        public /* synthetic */ void lambda$onNetworkQualityChanged$1$VisualCallReceiveActivity$5(DingRtcEngine.DingRtcNetworkQuality upQuality, DingRtcEngine.DingRtcNetworkQuality downQuality, String s) {
            if (upQuality.getValue() == ALI_RTC_INTERFACE.TransportStatus.Network_Disconnected.getValue() || downQuality.getValue() == ALI_RTC_INTERFACE.TransportStatus.Network_Disconnected.getValue()) {
                VisualCallReceiveActivity.this.mbytExit = (byte) 1;
                AVideoCallInterface.DiscardAVideoCall(VisualCallReceiveActivity.this.getIntent().getStringExtra(TtmlNode.ATTR_ID), ((int) (System.currentTimeMillis() - VisualCallReceiveActivity.this.mlStart)) / 1000, VisualCallReceiveActivity.this.callStyle == 2);
                VisualCallReceiveActivity.this.stopRinging();
                if (VisualCallReceiveActivity.this.VisualCallType == 3) {
                    VisualCallReceiveActivity.this.txtTip.setText(LocaleController.getString("visual_call_stop", R.string.visual_call_stop));
                    VisualCallReceiveActivity.this.txtTip.setVisibility(0);
                    VisualCallReceiveActivity.this.chrVisualcallTime.stop();
                    VisualCallReceiveActivity.this.txtTip.postDelayed(new $$Lambda$XBP5wqdfkxd6BRIGp0CRLqrqCB8(VisualCallReceiveActivity.this), AdaptiveTrackSelection.DEFAULT_MIN_TIME_BETWEEN_BUFFER_REEVALUTATION_MS);
                } else {
                    VisualCallReceiveActivity.this.txtTip.setText(LocaleController.getString("visual_call_stop", R.string.visual_call_stop));
                    VisualCallReceiveActivity.this.txtTip.setVisibility(0);
                    VisualCallReceiveActivity.this.txtTip.postDelayed(new $$Lambda$XBP5wqdfkxd6BRIGp0CRLqrqCB8(VisualCallReceiveActivity.this), AdaptiveTrackSelection.DEFAULT_MIN_TIME_BETWEEN_BUFFER_REEVALUTATION_MS);
                }
                VisualCallReceiveActivity.this.cancelCallingState();
            }
            if (VisualCallReceiveActivity.this.mbytExit != 1 && VisualCallReceiveActivity.this.callStyle == 2) {
                if (s.equals(Integer.valueOf(VisualCallReceiveActivity.this.mUser.id))) {
                    if (upQuality.getValue() > ALI_RTC_INTERFACE.TransportStatus.Network_Bad.getValue()) {
                        VisualCallReceiveActivity.this.txtTip.setText(LocaleController.getString("visual_call_other_net_bad", R.string.visual_call_other_net_bad));
                        VisualCallReceiveActivity.this.txtTip.setVisibility(0);
                        VisualCallReceiveActivity.this.mlTipShow = System.currentTimeMillis();
                        return;
                    } else {
                        if (VisualCallReceiveActivity.this.txtTip.getVisibility() == 0 && System.currentTimeMillis() - VisualCallReceiveActivity.this.mlTipShow > AdaptiveTrackSelection.DEFAULT_MIN_TIME_BETWEEN_BUFFER_REEVALUTATION_MS) {
                            VisualCallReceiveActivity.this.txtTip.setVisibility(8);
                            return;
                        }
                        return;
                    }
                }
                if (downQuality.getValue() > ALI_RTC_INTERFACE.TransportStatus.Network_Bad.getValue()) {
                    VisualCallReceiveActivity.this.txtTip.setText(LocaleController.getString("visual_call_net_bad", R.string.visual_call_net_bad));
                    VisualCallReceiveActivity.this.txtTip.setVisibility(0);
                    VisualCallReceiveActivity.this.mlTipShow = System.currentTimeMillis();
                } else if (VisualCallReceiveActivity.this.txtTip.getVisibility() == 0 && System.currentTimeMillis() - VisualCallReceiveActivity.this.mlTipShow > AdaptiveTrackSelection.DEFAULT_MIN_TIME_BETWEEN_BUFFER_REEVALUTATION_MS) {
                    VisualCallReceiveActivity.this.txtTip.setVisibility(8);
                }
            }
        }

        @Override // com.ding.rtc.DingRtcEngineEventListener
        public void onConnectionLost() {
            VisualCallReceiveActivity.this.runOnUiThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.visualcall.-$$Lambda$VisualCallReceiveActivity$5$2BmThun1wGBq9qhpPXdiuQ45VZI
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$onConnectionLost$2$VisualCallReceiveActivity$5();
                }
            });
        }

        public /* synthetic */ void lambda$onConnectionLost$2$VisualCallReceiveActivity$5() {
            VisualCallReceiveActivity.this.txtTip.setText(LocaleController.getString("visual_call_network_disconnect", R.string.visual_call_network_disconnect));
            VisualCallReceiveActivity.this.txtTip.setVisibility(0);
        }

        @Override // com.ding.rtc.DingRtcEngineEventListener
        public void onTryToReconnect() {
            VisualCallReceiveActivity.this.runOnUiThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.visualcall.-$$Lambda$VisualCallReceiveActivity$5$Lz2gjwbAU07B9bCSAa2pyhLwtY0
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$onTryToReconnect$3$VisualCallReceiveActivity$5();
                }
            });
        }

        public /* synthetic */ void lambda$onTryToReconnect$3$VisualCallReceiveActivity$5() {
            VisualCallReceiveActivity.this.txtTip.setText(LocaleController.getString("visual_call_retry_connect", R.string.visual_call_retry_connect));
            VisualCallReceiveActivity.this.txtTip.setVisibility(0);
        }

        public /* synthetic */ void lambda$onConnectionRecovery$4$VisualCallReceiveActivity$5() {
            VisualCallReceiveActivity.this.txtTip.setVisibility(8);
        }

        @Override // com.ding.rtc.DingRtcEngineEventListener
        public void onConnectionRecovery() {
            VisualCallReceiveActivity.this.runOnUiThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.visualcall.-$$Lambda$VisualCallReceiveActivity$5$Fyx7ORAgxDewMYsCmol3_W-EZgs
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$onConnectionRecovery$4$VisualCallReceiveActivity$5();
                }
            });
        }

        @Override // com.ding.rtc.DingRtcEngineEventListener
        public void onRemoteUserOffLineNotify(String uid, DingRtcEngine.DingRtcUserOfflineReason reason) {
            VisualCallReceiveActivity.this.updateRemoteDisplay(uid, DingRtcEngine.DingRtcVideoTrack.DingRtcVideoTrackNo.getValue());
            VisualCallReceiveActivity.this.removeRemoteUser(uid);
        }

        @Override // com.ding.rtc.DingRtcEngineEventListener
        public void onRemoteUserOnLineNotify(final String uid, int elapsed) {
            KLog.d("----------远端用户上线通知" + uid);
            if (TextUtils.isEmpty(VisualCallReceiveActivity.this.currentUid)) {
                VisualCallReceiveActivity.this.currentUid = uid;
                VisualCallReceiveActivity.this.runOnUiThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.visualcall.-$$Lambda$VisualCallReceiveActivity$5$pGzHBY3FtsJ2FxpO1vRMpFNa7MM
                    @Override // java.lang.Runnable
                    public final void run() {
                        this.f$0.lambda$onRemoteUserOnLineNotify$6$VisualCallReceiveActivity$5(uid);
                    }
                });
            }
        }

        public /* synthetic */ void lambda$onRemoteUserOnLineNotify$6$VisualCallReceiveActivity$5(String uid) {
            VisualCallReceiveActivity.this.addRemoteUser(uid);
            VisualCallReceiveActivity.this.VisualCallType = 3;
            VisualCallReceiveActivity.this.imgVisualcall.setVisibility(0);
            VisualCallReceiveActivity.this.relVideoUser.setVisibility(8);
            VisualCallReceiveActivity.this.mlStart = System.currentTimeMillis();
            VisualCallReceiveActivity.this.chrVisualcallTime.setVisibility(0);
            VisualCallReceiveActivity.this.chrVisualcallTime.setBase(SystemClock.elapsedRealtime());
            VisualCallReceiveActivity.this.chrVisualcallTime.start();
            if (VisualCallReceiveActivity.this.sfLocalView != null) {
                VisualCallReceiveActivity.this.sfLocalView.setAlpha(1.0f);
            }
            VisualCallReceiveActivity.this.txtVisualcallStatus.setText(LocaleController.getString("Str_visualcalling", R.string.Str_visualcalling));
            VisualCallReceiveActivity.this.txtVisualcallStatus.setVisibility(0);
            VisualCallReceiveActivity.this.txtMask.setVisibility(8);
            VisualCallReceiveActivity.this.txtMask.postDelayed(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.visualcall.-$$Lambda$VisualCallReceiveActivity$5$6o3APsuEhotBneFB0AGJ_meBauI
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$null$5$VisualCallReceiveActivity$5();
                }
            }, AdaptiveTrackSelection.DEFAULT_MIN_TIME_BETWEEN_BUFFER_REEVALUTATION_MS);
            if (ApplicationLoader.mbytAVideoCallBusy == 3 && VisualCallReceiveActivity.this.myservice != null) {
                VisualCallReceiveActivity.this.myservice.setView(null, null, VisualCallReceiveActivity.this.chrVisualcallTime.getBase(), VisualCallReceiveActivity.this.mChannel);
            }
            VisualCallReceiveActivity.this.changeStatusView();
        }

        public /* synthetic */ void lambda$null$5$VisualCallReceiveActivity$5() {
            VisualCallReceiveActivity.this.txtVisualcallStatus.setVisibility(8);
        }

        @Override // com.ding.rtc.DingRtcEngineEventListener
        public void onRemoteTrackAvailableNotify(String uid, DingRtcEngine.DingRtcAudioTrack audioTrack, DingRtcEngine.DingRtcVideoTrack videoTrack) {
            StringBuilder sb = new StringBuilder();
            sb.append("---------视频流变化");
            sb.append(videoTrack.getValue() == DingRtcEngine.DingRtcVideoTrack.DingRtcVideoTrackNo.getValue() ? "   没有视频" : "   有视频");
            KLog.d(sb.toString());
            StringBuilder sb2 = new StringBuilder();
            sb2.append("---------音频流变化");
            sb2.append(audioTrack.getValue() == DingRtcEngine.DingRtcAudioTrack.DingRtcAudioTrackNo.getValue() ? "   没有音频" : "   有音频");
            KLog.d(sb2.toString());
            VisualCallReceiveActivity.this.updateRemoteDisplay(uid, videoTrack.getValue());
            VisualCallReceiveActivity.this.runOnUiThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.visualcall.-$$Lambda$VisualCallReceiveActivity$5$m5W34g8NT3K-x8T56xdC9p5aJIE
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$onRemoteTrackAvailableNotify$7$VisualCallReceiveActivity$5();
                }
            });
        }

        public /* synthetic */ void lambda$onRemoteTrackAvailableNotify$7$VisualCallReceiveActivity$5() {
            VisualCallReceiveActivity.this.VisualCallType = 3;
            if (VisualCallReceiveActivity.this.callStyle == 2) {
                VisualCallReceiveActivity.this.chartVideoContainer.setVisibility(0);
            }
        }
    }

    private void initEventListener() {
        this.mEventListener = new AnonymousClass5();
    }

    @Override // android.app.Activity
    public void onBackPressed() {
        XDialog.Builder builder = new XDialog.Builder(this);
        builder.setTitle(LocaleController.getString("Tips", R.string.Tips));
        builder.setMessage(LocaleController.getString(R.string.visual_call_exit_ask));
        builder.setPositiveButton(LocaleController.getString("Set", R.string.Set), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.visualcall.-$$Lambda$VisualCallReceiveActivity$40xI8J2ciqHd3XI-kM7hSDE3evA
            @Override // android.content.DialogInterface.OnClickListener
            public final void onClick(DialogInterface dialogInterface, int i) {
                this.f$0.lambda$onBackPressed$6$VisualCallReceiveActivity(dialogInterface, i);
            }
        });
        builder.setNegativeButton(LocaleController.getString("Cancel", R.string.Cancel), null);
        XDialog dialog = builder.create();
        dialog.show();
    }

    public /* synthetic */ void lambda$onBackPressed$6$VisualCallReceiveActivity(DialogInterface dialogInterface, int i) {
        this.mbytNoOp = (byte) 1;
        if (this.VisualCallType == 3) {
            AVideoCallInterface.DiscardAVideoCall(getIntent().getStringExtra(TtmlNode.ATTR_ID), ((int) (System.currentTimeMillis() - this.mlStart)) / 1000, this.callStyle == 2);
        } else {
            AVideoCallInterface.DiscardAVideoCall(getIntent().getStringExtra(TtmlNode.ATTR_ID), this.RESPONSE_REFUSE, this.callStyle == 2);
        }
        stopRinging();
        cancelCallingState();
        super.onBackPressed();
    }

    @Override // android.app.Activity
    protected void onResume() {
        super.onResume();
        KLog.d("--------------------?");
        if (this.mblnUnProcessChooseVoiceTip) {
            this.txtTip.setText(LocaleController.getString(R.string.visual_call_receive_to_voice));
            setTipPos();
            this.txtTip.setVisibility(0);
            this.txtTip.postDelayed(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.visualcall.-$$Lambda$VisualCallReceiveActivity$Xkf1Yg_0qvnL286JQi81nyhH06E
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$onResume$7$VisualCallReceiveActivity();
                }
            }, AdaptiveTrackSelection.DEFAULT_MIN_TIME_BETWEEN_BUFFER_REEVALUTATION_MS);
            this.mblnUnProcessChooseVoiceTip = false;
        }
        if (this.myservice != null && this.mbytIsForeground == 1) {
            View videoView = this.myservice.getViewBig(false);
            View smallView = this.myservice.getViewSmall(false);
            if (this.callStyle == 2 && videoView != null) {
                if (this.VisualCallType == 3) {
                    changeLocalPreview(null);
                }
                if (this.VisualCallType == 3) {
                    changeLocalPreview(null);
                }
                this.llBigWindow.addView(videoView, new ViewGroup.LayoutParams(-1, -1));
                if (smallView != null) {
                    this.chartVideoContainer.addView(smallView, new ViewGroup.LayoutParams(-1, -1));
                }
                this.chartVideoContainer.setVisibility(0);
            }
        }
        if (this.misConnect) {
            unbindService(this.mVideoServiceConnection);
            this.misConnect = false;
        }
        this.mbytIsForeground = (byte) 1;
    }

    public /* synthetic */ void lambda$onResume$7$VisualCallReceiveActivity() {
        this.txtTip.setVisibility(8);
    }

    @Override // android.app.Activity
    protected void onStop() {
        this.mbytIsForeground = AndroidUtilities.isAppOnForeground(this) ? (byte) 1 : (byte) 0;
        super.onStop();
    }

    @Override // android.app.Activity
    protected void onStart() {
        super.onStart();
    }

    @Override // im.uwrkaxlmjj.ui.hui.visualcall.BaseCallActivity
    protected void changeLocalPreview(SurfaceView view) {
        if (view != null) {
            if (this.mbytLocalPos == 0) {
                this.mbytLocalPos = (byte) 1;
            } else {
                this.mbytLocalPos = (byte) 0;
            }
        }
        if (this.mbytLocalPos == 0) {
            this.sfLocalView.setVisibility(0);
            this.llBigRemoteView.setVisibility(0);
            this.sfSmallView.setVisibility(0);
            this.llSmallRemoteView.setVisibility(8);
            View v = this.llSmallRemoteView.getChildAt(0);
            this.llSmallRemoteView.removeAllViews();
            this.llBigRemoteView.removeAllViews();
            if (view == null) {
                if (v != null) {
                    ((SurfaceView) v).setZOrderOnTop(false);
                    ((SurfaceView) v).setZOrderMediaOverlay(false);
                    this.llBigRemoteView.addView(v, new LinearLayout.LayoutParams(-1, -1));
                }
            } else {
                this.llBigRemoteView.addView(view, new LinearLayout.LayoutParams(-1, -1));
            }
            if (this.mAliRtcEngine != null) {
                this.sfSmallView.setZOrderOnTop(true);
                this.sfSmallView.setZOrderMediaOverlay(true);
                this.mAliRtcEngine.setLocalViewConfig(this.aliVideoCanvasSmall, DingRtcEngine.DingRtcVideoTrack.DingRtcVideoTrackCamera);
                this.mAliRtcEngine.startPreview();
            }
            this.mbytLocalPos = (byte) 1;
            return;
        }
        this.sfLocalView.setVisibility(0);
        this.llBigRemoteView.setVisibility(8);
        this.sfSmallView.setVisibility(0);
        this.llSmallRemoteView.setVisibility(0);
        this.llSmallRemoteView.removeAllViews();
        View v2 = this.llBigRemoteView.getChildAt(0);
        this.llBigRemoteView.removeAllViews();
        if (view == null) {
            if (v2 != null) {
                ((SurfaceView) v2).setZOrderOnTop(true);
                this.llSmallRemoteView.addView(v2, new LinearLayout.LayoutParams(-1, -1));
            }
        } else {
            view.setZOrderOnTop(true);
            view.setZOrderMediaOverlay(true);
            this.llSmallRemoteView.addView(view, new LinearLayout.LayoutParams(-1, -1));
        }
        if (this.mAliRtcEngine != null) {
            this.sfLocalView.setZOrderOnTop(true);
            this.sfLocalView.setZOrderMediaOverlay(true);
            this.mAliRtcEngine.setLocalViewConfig(this.aliVideoCanvasBig, DingRtcEngine.DingRtcVideoTrack.DingRtcVideoTrackCamera);
            this.mAliRtcEngine.startPreview();
        }
        this.mbytLocalPos = (byte) 0;
    }

    @Override // im.uwrkaxlmjj.ui.hui.visualcall.BaseCallActivity
    protected void changePopWindow() {
        View view = null;
        View smallView = null;
        if (this.callStyle == 2) {
            if (this.mbytLocalPos == 0) {
                view = this.sfLocalView;
                smallView = this.llSmallRemoteView;
            } else {
                view = this.llBigRemoteView;
                smallView = this.sfSmallView;
            }
            this.llBigWindow.removeView(view);
            this.chartVideoContainer.removeView(smallView);
        }
        this.myservice.setCallStyle(this.callStyle);
        this.myservice.setBlnCaller(false);
        if (this.VisualCallType == 3) {
            this.myservice.setView(view, smallView, this.chrVisualcallTime.getBase(), this.mChannel);
        } else {
            this.myservice.setView(view, smallView, -1000000L, this.mChannel);
        }
    }

    private void setTipPos() {
        RelativeLayout.LayoutParams layoutParams = (RelativeLayout.LayoutParams) this.txtTip.getLayoutParams();
        if (this.relVoiceUser.getVisibility() == 8) {
            this.txtTip.setGravity(17);
        } else {
            layoutParams.addRule(3, R.attr.rel_voice_user);
            layoutParams.topMargin = AndroidUtilities.dp(25.0f);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void changeToVoice(boolean blnCaller) {
        setAVideoUI();
        this.txtPreChangeToVoice.setVisibility(8);
        if (this.mbytIsForeground == 0) {
            this.mblnUnProcessChooseVoiceTip = true;
        } else {
            if (blnCaller) {
                this.txtTip.setText(LocaleController.getString(R.string.visual_call_caller_to_voice));
            } else {
                this.txtTip.setText(LocaleController.getString(R.string.visual_call_receive_to_voice));
            }
            setTipPos();
            this.txtTip.setVisibility(0);
            this.txtTip.postDelayed(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.visualcall.-$$Lambda$VisualCallReceiveActivity$IqDbh1hun-fVC8DDYjS-L-kb8Xo
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$changeToVoice$8$VisualCallReceiveActivity();
                }
            }, AdaptiveTrackSelection.DEFAULT_MIN_TIME_BETWEEN_BUFFER_REEVALUTATION_MS);
        }
        if (this.mAliRtcEngine != null) {
            if (this.mAliRtcEngine.isSpeakerphoneEnabled()) {
                this.mAliRtcEngine.enableSpeakerphone(false);
            }
            this.mAliRtcEngine.stopPreview();
        }
        if (this.VisualCallType == 3) {
            changeStatusView();
            this.linOperateA.setVisibility(0);
            this.linOperateB.setVisibility(0);
            this.linOperateC.setVisibility(0);
            this.chrVisualcallTime.setVisibility(0);
            this.llBigWindow.setVisibility(8);
            this.chartVideoContainer.setVisibility(8);
            this.txtOperateA.setText(LocaleController.getString(R.string.Str_visualcall_no_voice));
            this.txtOperateC.setText(LocaleController.getString(R.string.Str_visualcall_hands_free));
            if (this.mIsAudioCapture) {
                this.imgOperateA.setBackgroundResource(R.drawable.visualcall_no_voice);
            } else {
                this.imgOperateA.setBackgroundResource(R.drawable.visualcall_no_voice_selected);
            }
            if (this.mAliRtcEngine != null) {
                if (this.mAliRtcEngine.isSpeakerphoneEnabled()) {
                    this.imgOperateC.setBackgroundResource(R.drawable.visual_hands_free_selected);
                } else {
                    this.imgOperateC.setBackgroundResource(R.drawable.visualcall_hands_free);
                }
            }
        }
    }

    public /* synthetic */ void lambda$changeToVoice$8$VisualCallReceiveActivity() {
        this.txtTip.setVisibility(8);
    }
}
