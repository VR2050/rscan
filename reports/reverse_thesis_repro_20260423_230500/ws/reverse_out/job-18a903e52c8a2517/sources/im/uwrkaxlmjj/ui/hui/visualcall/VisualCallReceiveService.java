package im.uwrkaxlmjj.ui.hui.visualcall;

import android.app.Notification;
import android.app.PendingIntent;
import android.app.Service;
import android.content.Context;
import android.content.Intent;
import android.graphics.BitmapFactory;
import android.os.Build;
import android.os.Handler;
import android.os.IBinder;
import android.widget.Toast;
import androidx.core.app.NotificationCompat;
import com.google.android.exoplayer2.C;
import com.google.android.exoplayer2.extractor.ogg.DefaultOggSeeker;
import com.google.android.exoplayer2.text.ttml.TtmlNode;
import com.google.android.exoplayer2.trackselection.AdaptiveTrackSelection;
import com.socks.library.KLog;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.ApplicationLoader;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.messenger.NotificationCenter;
import im.uwrkaxlmjj.tgnet.TLRPCCall;
import im.uwrkaxlmjj.ui.LaunchActivity;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.helper.DatabaseInstance;
import java.util.ArrayList;
import java.util.Random;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class VisualCallReceiveService extends Service implements NotificationCenter.NotificationCenterDelegate {
    private long mlLastReqTime;
    private String strId;
    private String ID = "0x110066";
    private Runnable runnable = new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.visualcall.-$$Lambda$blkIixecGvFUb7zvALzB5IV9l-c
        @Override // java.lang.Runnable
        public final void run() {
            RingUtils.stopSoundPoolRing();
        }
    };
    private Handler handler = new Handler();

    @Override // android.app.Service
    public IBinder onBind(Intent intent) {
        return null;
    }

    @Override // android.app.Service
    public int onStartCommand(final Intent intent, int flags, int startId) {
        RingUtils.stopMediaPlayerRing();
        VisualCallRequestBean bean = DatabaseInstance.queryVisualCallById(intent.getStringExtra(TtmlNode.ATTR_ID));
        if (bean == null) {
            KLog.d("----------收到音视频请求 type = " + intent.getStringExtra(TtmlNode.ATTR_ID) + " " + (System.currentTimeMillis() - this.mlLastReqTime));
            this.handler.removeCallbacks(this.runnable);
            if (System.currentTimeMillis() - this.mlLastReqTime > AdaptiveTrackSelection.DEFAULT_MIN_TIME_BETWEEN_BUFFER_REEVALUTATION_MS) {
                this.mlLastReqTime = System.currentTimeMillis();
                if (ApplicationLoader.mbytAVideoCallBusy == 0) {
                    if (AndroidUtilities.isAppOnForeground(this)) {
                        if (DatabaseInstance.getVisualCallCount() < 1) {
                            boolean blnVideo = intent.getBooleanExtra("video", false);
                            Intent actIntent = new Intent(this, (Class<?>) VisualCallReceiveActivity.class);
                            actIntent.putExtra("video", blnVideo);
                            actIntent.putExtra(TtmlNode.ATTR_ID, intent.getStringExtra(TtmlNode.ATTR_ID));
                            actIntent.putExtra("admin_id", intent.getIntExtra("admin_id", 0));
                            actIntent.putExtra("app_id", intent.getStringExtra("app_id"));
                            actIntent.putExtra("token", intent.getStringExtra("token"));
                            actIntent.putStringArrayListExtra("gslb", intent.getStringArrayListExtra("gslb"));
                            actIntent.putExtra("json", intent.getStringExtra("json"));
                            actIntent.putExtra("from", 0);
                            actIntent.addFlags(C.ENCODING_PCM_MU_LAW);
                            startActivity(actIntent);
                            new Handler().postDelayed(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.visualcall.-$$Lambda$VisualCallReceiveService$lK0T9wcdDLKlkOxKz3bgVb7yTrI
                                @Override // java.lang.Runnable
                                public final void run() {
                                    VisualCallReceiveService.lambda$onStartCommand$0(intent);
                                }
                            }, 3000L);
                        } else {
                            AVideoCallInterface.IsBusyingNow(intent.getStringExtra(TtmlNode.ATTR_ID));
                        }
                    } else if (DatabaseInstance.getVisualCallCount() < 1) {
                        RingUtils.playRingBySoundPool(this);
                        this.strId = intent.getStringExtra(TtmlNode.ATTR_ID);
                        VisualCallRequestParaBean paraBean = new VisualCallRequestParaBean();
                        paraBean.setStrId(intent.getStringExtra(TtmlNode.ATTR_ID));
                        paraBean.setVideo(intent.getBooleanExtra("video", false));
                        paraBean.setAdmin_id(intent.getIntExtra("admin_id", 0));
                        paraBean.setApp_id(intent.getStringExtra("app_id"));
                        paraBean.setToken(intent.getStringExtra("token"));
                        String strGslb = "";
                        ArrayList<String> arrayList = intent.getStringArrayListExtra("gslb");
                        for (int i = 0; i < arrayList.size(); i++) {
                            if (strGslb.equals("")) {
                                String strGslb2 = arrayList.get(i);
                                strGslb = strGslb2;
                            } else {
                                strGslb = strGslb + "," + arrayList.get(i);
                            }
                        }
                        paraBean.setGslb(strGslb);
                        paraBean.setJson(intent.getStringExtra("json"));
                        DatabaseInstance.saveVisualCallPara(paraBean);
                        this.handler.postDelayed(this.runnable, 35000L);
                    } else {
                        AVideoCallInterface.IsBusyingNow(intent.getStringExtra(TtmlNode.ATTR_ID));
                    }
                    VisualCallRequestBean bean1 = new VisualCallRequestBean();
                    bean1.setStrId(intent.getStringExtra(TtmlNode.ATTR_ID));
                    bean1.setTimestamp(System.currentTimeMillis());
                    DatabaseInstance.saveVisualCallRequest(bean1);
                    return 1;
                }
                AVideoCallInterface.IsBusyingNow(intent.getStringExtra(TtmlNode.ATTR_ID));
                return 1;
            }
            AVideoCallInterface.IsBusyingNow(intent.getStringExtra(TtmlNode.ATTR_ID));
            return 1;
        }
        return 1;
    }

    static /* synthetic */ void lambda$onStartCommand$0(Intent intent) {
        if (ApplicationLoader.mbytAVideoCallBusy == 0) {
            AVideoCallInterface.IsBusyingNow(intent.getStringExtra(TtmlNode.ATTR_ID));
        }
    }

    private void WaitForCallReceiveActivity(final Intent intent) {
        new Thread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.visualcall.-$$Lambda$VisualCallReceiveService$j9YK3ahdwRuTZYdLAZ-RxG8IWq4
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$WaitForCallReceiveActivity$2$VisualCallReceiveService(intent);
            }
        }).start();
    }

    public /* synthetic */ void lambda$WaitForCallReceiveActivity$2$VisualCallReceiveService(final Intent intent) {
        int iCount = 0;
        while (ApplicationLoader.mbytAVideoCallBusy == 0) {
            try {
                Thread.sleep(500L);
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
            iCount++;
            if (iCount > 8 || ApplicationLoader.mbytAVideoCallBusy == 1) {
                break;
            }
        }
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.visualcall.-$$Lambda$VisualCallReceiveService$yvIWM8UcxXqY8O6B-nHXQdjTED0
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$1$VisualCallReceiveService(intent);
            }
        });
    }

    public /* synthetic */ void lambda$null$1$VisualCallReceiveService(Intent intent) {
        RingUtils.playRingBySoundPool(this);
        if (ApplicationLoader.mbytAVideoCallBusy == 0) {
            startActivity(intent);
        }
    }

    @Override // android.app.Service
    public void onCreate() {
        super.onCreate();
        int i = Build.VERSION.SDK_INT;
        NotificationCenter.getGlobalInstance().addObserver(this, NotificationCenter.reecivedAVideoDiscarded);
    }

    public Notification createCompatibleNotification(Context context) {
        Random ra = new Random();
        int iRand = ra.nextInt(DefaultOggSeeker.MATCH_BYTE_RANGE) + 100;
        this.ID = "0x" + iRand;
        Intent intentChart = new Intent(this, (Class<?>) LaunchActivity.class);
        PendingIntent pendingIntent = PendingIntent.getActivity(context, 1, intentChart, 134217728);
        return new NotificationCompat.Builder(context, this.ID).setContentTitle(LocaleController.getString("visual_call_doing", R.string.visual_call_doing)).setContentText(LocaleController.getString("visual_call_doing_now", R.string.visual_call_doing_now)).setSmallIcon(R.id.ic_launcher).setContentIntent(pendingIntent).setOngoing(false).setWhen(System.currentTimeMillis()).setSound(null).setChannelId("to-do-it").setPriority(-2).build();
    }

    public Notification createMainNotification(Context context) {
        Intent intentChart = new Intent(this, (Class<?>) VisualCallReceiveActivity.class);
        PendingIntent pendingIntent = PendingIntent.getActivity(this, 0, intentChart, 0);
        Notification.Builder builder = new Notification.Builder(getApplicationContext());
        builder.setContentIntent(pendingIntent).setLargeIcon(BitmapFactory.decodeResource(getResources(), R.id.ic_launcher)).setContentTitle(LocaleController.getString("visual_call_doing", R.string.visual_call_doing)).setContentText(LocaleController.getString("visual_call_doing_now", R.string.visual_call_doing_now)).setSmallIcon(R.id.ic_launcher).setWhen(System.currentTimeMillis()).setDefaults(2).setPriority(1);
        Notification notification = builder.build();
        notification.defaults = 1;
        notification.flags |= 16;
        notification.flags = 2 | notification.flags;
        notification.flags |= 32;
        return notification;
    }

    @Override // android.app.Service
    public void onDestroy() {
        stopForeground(true);
        NotificationCenter.getGlobalInstance().removeObserver(this, NotificationCenter.reecivedAVideoDiscarded);
        super.onDestroy();
    }

    @Override // im.uwrkaxlmjj.messenger.NotificationCenter.NotificationCenterDelegate
    public void didReceivedNotification(int id, int account, Object... args) {
        TLRPCCall.TL_UpdateMeetCallDiscarded discarded;
        if (!AndroidUtilities.isAppOnForeground(this) && id == NotificationCenter.reecivedAVideoDiscarded && (discarded = (TLRPCCall.TL_UpdateMeetCallDiscarded) args[0]) != null && discarded.id.equals(this.strId)) {
            Toast.makeText(this, LocaleController.getString("visual_call_other_side_cancel", R.string.visual_call_other_side_cancel), 1).show();
            DatabaseInstance.deleteVisualCallRequest();
            RingUtils.stopSoundPoolRing();
        }
    }
}
