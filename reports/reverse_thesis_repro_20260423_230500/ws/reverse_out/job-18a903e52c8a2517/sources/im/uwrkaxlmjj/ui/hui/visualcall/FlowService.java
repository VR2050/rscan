package im.uwrkaxlmjj.ui.hui.visualcall;

import android.app.Service;
import android.content.ComponentName;
import android.content.Intent;
import android.graphics.Color;
import android.graphics.PorterDuff;
import android.graphics.drawable.Drawable;
import android.os.Binder;
import android.os.Build;
import android.os.Handler;
import android.os.IBinder;
import android.os.SystemClock;
import android.util.Log;
import android.view.LayoutInflater;
import android.view.MotionEvent;
import android.view.View;
import android.view.ViewGroup;
import android.view.WindowManager;
import android.widget.Chronometer;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.RelativeLayout;
import com.blankj.utilcode.constant.TimeConstants;
import com.google.android.exoplayer2.C;
import com.king.zxing.util.LogUtils;
import com.socks.library.KLog;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.ApplicationLoader;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.messenger.NotificationCenter;
import im.uwrkaxlmjj.messenger.utils.ShapeUtils;
import im.uwrkaxlmjj.tgnet.TLRPCCall;
import im.uwrkaxlmjj.ui.components.toast.ToastUtils;
import im.uwrkaxlmjj.ui.hviews.helper.MryDisplayHelper;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class FlowService extends Service implements NotificationCenter.NotificationCenterDelegate {
    private boolean clickflag;
    private LayoutInflater inflater;
    private boolean isMove;
    private LinearLayout lin_voice;
    private View mFloatingLayout;
    private int mStartX;
    private int mStartY;
    private int mStopX;
    private int mStopY;
    private String mStrId;
    private Chronometer mTimer;
    private int mTouchCurrentX;
    private int mTouchCurrentY;
    private int mTouchStartX;
    private int mTouchStartY;
    private WindowManager mWindowManager;
    private RelativeLayout smallSizePreviewLayout;
    private RelativeLayout smallWindow;
    private WindowManager.LayoutParams wmParams;
    private int callStyle = 1;
    private byte mbytExit = 0;
    private boolean blnCaller = true;
    private boolean mblnUnProcessChooseVoiceTip = false;
    Handler mHandler = new Handler();

    @Override // android.app.Service
    public IBinder onBind(Intent intent) {
        return new MyBinder();
    }

    public void setView(View mView, View smallView, long lTimebase, String strId) {
        this.mStrId = strId;
        this.mbytExit = (byte) 0;
        if (mView != null) {
            this.smallSizePreviewLayout.addView(mView, new FrameLayout.LayoutParams(-1, -1));
        }
        if (smallView != null) {
            this.smallWindow.addView(smallView, new FrameLayout.LayoutParams(-1, -1));
        }
        if (lTimebase == -1000000) {
            this.mTimer.setText(LocaleController.getString("visual_call_small_waiting", R.string.visual_call_small_waiting));
        } else {
            this.mTimer.setBase(lTimebase);
            this.mTimer.start();
        }
    }

    public View getViewBig(boolean blnVis) {
        View view = this.smallSizePreviewLayout.getChildAt(0);
        this.smallSizePreviewLayout.removeAllViews();
        if (!blnVis) {
            this.smallSizePreviewLayout.setVisibility(8);
        }
        return view;
    }

    public View getViewSmall(boolean blnVis) {
        View view = this.smallWindow.getChildAt(0);
        this.smallWindow.removeAllViews();
        if (!blnVis) {
            this.smallWindow.setVisibility(8);
        }
        return view;
    }

    @Override // im.uwrkaxlmjj.messenger.NotificationCenter.NotificationCenterDelegate
    public void didReceivedNotification(int id, int account, Object... args) {
        TLRPCCall.TL_UpdateMeetChangeCall changeCall;
        if (id == NotificationCenter.hideAVideoFloatWindow) {
            if (((Integer) args[0]).intValue() == 1) {
                this.mFloatingLayout.setVisibility(8);
                return;
            }
            this.mFloatingLayout.setVisibility(0);
            if (this.mblnUnProcessChooseVoiceTip) {
                ToastUtils.show((CharSequence) LocaleController.getString("visual_call_receive_to_voice", R.string.visual_call_receive_to_voice));
                this.mblnUnProcessChooseVoiceTip = false;
                return;
            }
            return;
        }
        if (id == NotificationCenter.reecivedAVideoDiscarded) {
            TLRPCCall.TL_UpdateMeetCallDiscarded discarded = (TLRPCCall.TL_UpdateMeetCallDiscarded) args[0];
            if (discarded != null && discarded.id.equals(this.mStrId)) {
                this.mbytExit = (byte) 1;
                if (AndroidUtilities.isAppOnForeground(this)) {
                    this.mTimer.stop();
                    this.mTimer.setText(LocaleController.getString("VoipCallEnded", R.string.VoipCallEnded));
                    return;
                }
                return;
            }
            return;
        }
        if (id == NotificationCenter.receivedAVideoCallChangeVoice && (changeCall = (TLRPCCall.TL_UpdateMeetChangeCall) args[0]) != null && changeCall.id.equals(this.mStrId)) {
            int iVis = this.mFloatingLayout.getVisibility();
            setCallStyle(1);
            getViewBig(false);
            getViewSmall(false);
            if (iVis == 8) {
                this.mblnUnProcessChooseVoiceTip = true;
                this.mFloatingLayout.setVisibility(8);
            } else {
                ToastUtils.show((CharSequence) LocaleController.getString("visual_call_receive_to_voice", R.string.visual_call_receive_to_voice));
            }
        }
    }

    public class MyBinder extends Binder {
        public MyBinder() {
        }

        public FlowService getService() {
            return FlowService.this;
        }
    }

    public void setCallStyle(int callStyle) {
        this.callStyle = callStyle;
        if (callStyle == 1) {
            this.lin_voice.setVisibility(0);
            this.smallSizePreviewLayout.setVisibility(8);
            this.smallWindow.setVisibility(8);
            this.lin_voice.setBackground(ShapeUtils.createStrokeAndFill(Color.rgb(225, 225, 225), 1.0f, AndroidUtilities.dp(5.0f), -1));
            return;
        }
        this.lin_voice.setVisibility(8);
        this.smallSizePreviewLayout.setVisibility(0);
        this.smallWindow.setVisibility(0);
    }

    private class MyRunnable implements Runnable {
        private MyRunnable() {
        }

        @Override // java.lang.Runnable
        public void run() {
            FlowService.this.mHandler.postDelayed(this, 1000L);
        }
    }

    @Override // android.app.Service
    public void onCreate() {
        super.onCreate();
        NotificationCenter.getGlobalInstance().addObserver(this, NotificationCenter.hideAVideoFloatWindow);
        NotificationCenter.getGlobalInstance().addObserver(this, NotificationCenter.reecivedAVideoDiscarded);
        NotificationCenter.getGlobalInstance().addObserver(this, NotificationCenter.receivedAVideoCallChangeVoice);
        initWindow();
        initFloating();
    }

    @Override // android.app.Service
    public int onStartCommand(Intent intent, int flags, int startId) {
        return super.onStartCommand(intent, flags, startId);
    }

    @Override // android.app.Service
    public void onDestroy() {
        super.onDestroy();
        View view = this.mFloatingLayout;
        if (view != null) {
            this.mWindowManager.removeView(view);
        }
        NotificationCenter.getGlobalInstance().removeObserver(this, NotificationCenter.hideAVideoFloatWindow);
        NotificationCenter.getGlobalInstance().removeObserver(this, NotificationCenter.reecivedAVideoDiscarded);
        NotificationCenter.getGlobalInstance().removeObserver(this, NotificationCenter.receivedAVideoCallChangeVoice);
    }

    private void initWindow() {
        this.mWindowManager = (WindowManager) getApplicationContext().getSystemService("window");
        StringBuilder sb = new StringBuilder();
        sb.append("kong");
        sb.append(this.mWindowManager == null);
        Log.e("-------", sb.toString());
        WindowManager.LayoutParams paramas = getParamas();
        this.wmParams = paramas;
        paramas.gravity = 51;
        this.wmParams.x = 70;
        this.wmParams.y = 210;
        LayoutInflater layoutInflaterFrom = LayoutInflater.from(getApplicationContext());
        this.inflater = layoutInflaterFrom;
        this.mFloatingLayout = layoutInflaterFrom.inflate(R.layout.flow_visualcall, (ViewGroup) null);
        if (Build.VERSION.SDK_INT >= 26) {
            this.wmParams.type = 2038;
        } else {
            this.wmParams.type = 2003;
        }
        this.mWindowManager.addView(this.mFloatingLayout, this.wmParams);
    }

    private WindowManager.LayoutParams getParamas() {
        WindowManager.LayoutParams layoutParams = new WindowManager.LayoutParams();
        this.wmParams = layoutParams;
        layoutParams.type = 2005;
        this.wmParams.flags = 327976;
        this.wmParams.format = -3;
        this.wmParams.width = -2;
        this.wmParams.height = -2;
        return this.wmParams;
    }

    private void initFloating() {
        this.smallSizePreviewLayout = (RelativeLayout) this.mFloatingLayout.findViewById(R.attr.lin_video);
        this.smallWindow = (RelativeLayout) this.mFloatingLayout.findViewById(R.attr.rl_small_window);
        this.lin_voice = (LinearLayout) this.mFloatingLayout.findViewById(R.attr.lin_voice);
        Chronometer chronometer = (Chronometer) this.mFloatingLayout.findViewById(R.attr.chr_timer);
        this.mTimer = chronometer;
        chronometer.setTextColor(Color.parseColor("#3BBCFF"));
        ImageView ivCall = (ImageView) this.mFloatingLayout.findViewById(R.attr.iv_call);
        Drawable drawable = getResources().getDrawable(R.drawable.visualcall_phone).mutate();
        drawable.setColorFilter(Color.parseColor("#3BBCFF"), PorterDuff.Mode.SRC_ATOP);
        ivCall.setImageDrawable(drawable);
        this.mTimer.setOnChronometerTickListener(new Chronometer.OnChronometerTickListener() { // from class: im.uwrkaxlmjj.ui.hui.visualcall.-$$Lambda$FlowService$40TheefQmgYZCx0fjUuvCtmWZAQ
            @Override // android.widget.Chronometer.OnChronometerTickListener
            public final void onChronometerTick(Chronometer chronometer2) {
                FlowService.lambda$initFloating$0(chronometer2);
            }
        });
        this.mFloatingLayout.findViewById(R.attr.fl_container).setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.visualcall.FlowService.1
            @Override // android.view.View.OnClickListener
            public void onClick(View v) {
                String actName;
                if (FlowService.this.mbytExit == 1) {
                    return;
                }
                KLog.d("-------点击");
                if (FlowService.this.blnCaller) {
                    actName = VisualCallActivity.class.getName();
                } else {
                    actName = VisualCallReceiveActivity.class.getName();
                }
                ComponentName componetName = new ComponentName(FlowService.this.getPackageName(), actName);
                Intent intent = new Intent();
                intent.setFlags(C.ENCODING_PCM_MU_LAW);
                if (FlowService.this.blnCaller) {
                    intent.setAction("m12345.cc.av.caller");
                    ApplicationLoader.mbytAVideoCallBusy = (byte) 2;
                } else {
                    intent.setAction("m12345.cc.av.receive");
                    ApplicationLoader.mbytAVideoCallBusy = (byte) 1;
                }
                intent.setComponent(componetName);
                FlowService.this.startActivity(intent);
            }
        });
        this.mFloatingLayout.findViewById(R.attr.fl_container).setOnTouchListener(new FloatingListener());
    }

    static /* synthetic */ void lambda$initFloating$0(Chronometer chronometer) {
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

    private class FloatingListener implements View.OnTouchListener {
        private FloatingListener() {
        }

        @Override // android.view.View.OnTouchListener
        public boolean onTouch(View v, MotionEvent event) {
            int action = event.getAction();
            if (action == 0) {
                FlowService.this.isMove = false;
                FlowService.this.mTouchStartX = (int) event.getRawX();
                FlowService.this.mTouchStartY = (int) event.getRawY();
                FlowService.this.mStartX = (int) event.getX();
                FlowService.this.mStartY = (int) event.getY();
            } else if (action == 1) {
                FlowService.this.mStopX = (int) event.getX();
                FlowService.this.mStopY = (int) event.getY();
                if (Math.abs(FlowService.this.mStartX - FlowService.this.mStopX) >= 3 || Math.abs(FlowService.this.mStartY - FlowService.this.mStopY) >= 3) {
                    int iScreenW = MryDisplayHelper.getScreenWidth(FlowService.this);
                    if (FlowService.this.wmParams.x > iScreenW / 2) {
                        if (FlowService.this.callStyle == 1) {
                            FlowService.this.wmParams.x = iScreenW - FlowService.this.lin_voice.getWidth();
                        } else {
                            FlowService.this.wmParams.x = iScreenW - FlowService.this.smallSizePreviewLayout.getWidth();
                        }
                    } else {
                        FlowService.this.wmParams.x = 0;
                    }
                    FlowService.this.mWindowManager.updateViewLayout(FlowService.this.mFloatingLayout, FlowService.this.wmParams);
                    FlowService.this.isMove = true;
                }
            } else if (action == 2) {
                FlowService.this.mTouchCurrentX = (int) event.getRawX();
                FlowService.this.mTouchCurrentY = (int) event.getRawY();
                FlowService.this.wmParams.x += FlowService.this.mTouchCurrentX - FlowService.this.mTouchStartX;
                FlowService.this.wmParams.y += FlowService.this.mTouchCurrentY - FlowService.this.mTouchStartY;
                FlowService.this.mWindowManager.updateViewLayout(FlowService.this.mFloatingLayout, FlowService.this.wmParams);
                FlowService flowService = FlowService.this;
                flowService.mTouchStartX = flowService.mTouchCurrentX;
                FlowService flowService2 = FlowService.this;
                flowService2.mTouchStartY = flowService2.mTouchCurrentY;
            }
            return FlowService.this.isMove;
        }
    }

    public void setBlnCaller(boolean blnCaller) {
        this.blnCaller = blnCaller;
    }
}
