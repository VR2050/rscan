package im.uwrkaxlmjj.messenger.voip;

import android.app.Activity;
import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.app.Service;
import android.bluetooth.BluetoothAdapter;
import android.content.BroadcastReceiver;
import android.content.ComponentName;
import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.SharedPreferences;
import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.graphics.Canvas;
import android.graphics.Paint;
import android.graphics.Path;
import android.graphics.PorterDuff;
import android.graphics.PorterDuffXfermode;
import android.graphics.drawable.BitmapDrawable;
import android.graphics.drawable.Icon;
import android.hardware.Sensor;
import android.hardware.SensorEvent;
import android.hardware.SensorEventListener;
import android.hardware.SensorManager;
import android.media.AudioAttributes;
import android.media.AudioManager;
import android.media.AudioTrack;
import android.media.MediaPlayer;
import android.media.RingtoneManager;
import android.media.SoundPool;
import android.net.ConnectivityManager;
import android.net.NetworkInfo;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.PowerManager;
import android.os.Vibrator;
import android.telecom.CallAudioState;
import android.telecom.Connection;
import android.telecom.DisconnectCause;
import android.telecom.PhoneAccount;
import android.telecom.PhoneAccountHandle;
import android.telecom.TelecomManager;
import android.telephony.TelephonyManager;
import android.text.SpannableString;
import android.text.TextUtils;
import android.text.style.ForegroundColorSpan;
import android.view.ViewGroup;
import android.widget.RemoteViews;
import androidx.core.app.NotificationCompat;
import com.google.android.exoplayer2.C;
import com.google.android.exoplayer2.DefaultRenderersFactory;
import com.google.android.exoplayer2.upstream.cache.ContentMetadata;
import com.google.firebase.remoteconfig.RemoteConfigConstants;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.ApplicationLoader;
import im.uwrkaxlmjj.messenger.BuildVars;
import im.uwrkaxlmjj.messenger.ContactsController;
import im.uwrkaxlmjj.messenger.FileLoader;
import im.uwrkaxlmjj.messenger.FileLog;
import im.uwrkaxlmjj.messenger.ImageLoader;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.messenger.MessagesController;
import im.uwrkaxlmjj.messenger.NotificationCenter;
import im.uwrkaxlmjj.messenger.NotificationsController;
import im.uwrkaxlmjj.messenger.StatsController;
import im.uwrkaxlmjj.messenger.UserConfig;
import im.uwrkaxlmjj.messenger.voip.VoIPController;
import im.uwrkaxlmjj.tgnet.ConnectionsManager;
import im.uwrkaxlmjj.tgnet.TLObject;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.ui.VoIPPermissionActivity;
import im.uwrkaxlmjj.ui.actionbar.BottomSheet;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.components.AvatarDrawable;
import im.uwrkaxlmjj.ui.components.voip.VoIPHelper;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.List;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes2.dex */
public abstract class VoIPBaseService extends Service implements SensorEventListener, AudioManager.OnAudioFocusChangeListener, VoIPController.ConnectionStateListener, NotificationCenter.NotificationCenterDelegate {
    public static final String ACTION_HEADSET_PLUG = "android.intent.action.HEADSET_PLUG";
    public static final int AUDIO_ROUTE_BLUETOOTH = 2;
    public static final int AUDIO_ROUTE_EARPIECE = 0;
    public static final int AUDIO_ROUTE_SPEAKER = 1;
    public static final int DISCARD_REASON_DISCONNECT = 2;
    public static final int DISCARD_REASON_HANGUP = 1;
    public static final int DISCARD_REASON_LINE_BUSY = 4;
    public static final int DISCARD_REASON_MISSED = 3;
    protected static final int ID_INCOMING_CALL_NOTIFICATION = 202;
    protected static final int ID_ONGOING_CALL_NOTIFICATION = 201;
    protected static final int PROXIMITY_SCREEN_OFF_WAKE_LOCK = 32;
    public static final int STATE_ENDED = 11;
    public static final int STATE_ESTABLISHED = 3;
    public static final int STATE_FAILED = 4;
    public static final int STATE_RECONNECTING = 5;
    public static final int STATE_WAIT_INIT = 1;
    public static final int STATE_WAIT_INIT_ACK = 2;
    protected static final boolean USE_CONNECTION_SERVICE = isDeviceCompatibleWithConnectionServiceAPI();
    protected static VoIPBaseService sharedInstance;
    protected boolean audioConfigured;
    protected BluetoothAdapter btAdapter;
    protected int callDiscardReason;
    protected Runnable connectingSoundRunnable;
    protected VoIPController controller;
    protected boolean controllerStarted;
    protected PowerManager.WakeLock cpuWakelock;
    protected boolean haveAudioFocus;
    protected boolean isBtHeadsetConnected;
    protected boolean isHeadsetPlugged;
    protected boolean isOutgoing;
    protected boolean isProximityNear;
    protected int lastError;
    protected NetworkInfo lastNetInfo;
    protected boolean micMute;
    protected boolean needPlayEndSound;
    protected Notification ongoingCallNotification;
    protected boolean playingSound;
    protected PowerManager.WakeLock proximityWakelock;
    protected MediaPlayer ringtonePlayer;
    protected int signalBarCount;
    protected SoundPool soundPool;
    protected int spBusyId;
    protected int spConnectingId;
    protected int spEndId;
    protected int spFailedID;
    protected int spPlayID;
    protected int spRingbackID;
    protected boolean speakerphoneStateToSet;
    protected CallConnection systemCallConnection;
    protected Runnable timeoutRunnable;
    protected Vibrator vibrator;
    private boolean wasEstablished;
    protected int currentAccount = -1;
    protected int currentState = 0;
    protected ArrayList<StateListener> stateListeners = new ArrayList<>();
    protected VoIPController.Stats stats = new VoIPController.Stats();
    protected VoIPController.Stats prevStats = new VoIPController.Stats();
    protected Runnable afterSoundRunnable = new Runnable() { // from class: im.uwrkaxlmjj.messenger.voip.VoIPBaseService.1
        @Override // java.lang.Runnable
        public void run() {
            VoIPBaseService.this.soundPool.release();
            if (VoIPBaseService.USE_CONNECTION_SERVICE) {
                return;
            }
            if (VoIPBaseService.this.isBtHeadsetConnected) {
                ((AudioManager) ApplicationLoader.applicationContext.getSystemService("audio")).stopBluetoothSco();
            }
            ((AudioManager) ApplicationLoader.applicationContext.getSystemService("audio")).setSpeakerphoneOn(false);
        }
    };
    protected long lastKnownDuration = 0;
    protected BroadcastReceiver receiver = new BroadcastReceiver() { // from class: im.uwrkaxlmjj.messenger.voip.VoIPBaseService.2
        @Override // android.content.BroadcastReceiver
        public void onReceive(Context context, Intent intent) {
            if (VoIPBaseService.ACTION_HEADSET_PLUG.equals(intent.getAction())) {
                VoIPBaseService.this.isHeadsetPlugged = intent.getIntExtra(RemoteConfigConstants.ResponseFieldKey.STATE, 0) == 1;
                if (VoIPBaseService.this.isHeadsetPlugged && VoIPBaseService.this.proximityWakelock != null && VoIPBaseService.this.proximityWakelock.isHeld()) {
                    VoIPBaseService.this.proximityWakelock.release();
                }
                VoIPBaseService.this.isProximityNear = false;
                VoIPBaseService.this.updateOutputGainControlState();
                return;
            }
            if ("android.net.conn.CONNECTIVITY_CHANGE".equals(intent.getAction())) {
                VoIPBaseService.this.updateNetworkType();
                return;
            }
            if ("android.bluetooth.headset.profile.action.CONNECTION_STATE_CHANGED".equals(intent.getAction())) {
                if (BuildVars.LOGS_ENABLED) {
                    FileLog.e("bt headset state = " + intent.getIntExtra("android.bluetooth.profile.extra.STATE", 0));
                }
                VoIPBaseService.this.updateBluetoothHeadsetState(intent.getIntExtra("android.bluetooth.profile.extra.STATE", 0) == 2);
                return;
            }
            if ("android.media.ACTION_SCO_AUDIO_STATE_UPDATED".equals(intent.getAction())) {
                int state = intent.getIntExtra("android.media.extra.SCO_AUDIO_STATE", 0);
                if (BuildVars.LOGS_ENABLED) {
                    FileLog.e("Bluetooth SCO state updated: " + state);
                }
                if (state == 0 && VoIPBaseService.this.isBtHeadsetConnected && (!VoIPBaseService.this.btAdapter.isEnabled() || VoIPBaseService.this.btAdapter.getProfileConnectionState(1) != 2)) {
                    VoIPBaseService.this.updateBluetoothHeadsetState(false);
                    return;
                }
                VoIPBaseService.this.bluetoothScoActive = state == 1;
                if (VoIPBaseService.this.bluetoothScoActive && VoIPBaseService.this.needSwitchToBluetoothAfterScoActivates) {
                    VoIPBaseService.this.needSwitchToBluetoothAfterScoActivates = false;
                    AudioManager am = (AudioManager) VoIPBaseService.this.getSystemService("audio");
                    am.setSpeakerphoneOn(false);
                    am.setBluetoothScoOn(true);
                }
                for (StateListener l : VoIPBaseService.this.stateListeners) {
                    l.onAudioSettingsChanged();
                }
                return;
            }
            if ("android.intent.action.PHONE_STATE".equals(intent.getAction())) {
                if (TelephonyManager.EXTRA_STATE_OFFHOOK.equals(intent.getStringExtra(RemoteConfigConstants.ResponseFieldKey.STATE))) {
                    VoIPBaseService.this.hangUp();
                }
            }
        }
    };
    private Boolean mHasEarpiece = null;
    protected int audioRouteToSet = 2;
    protected boolean bluetoothScoActive = false;
    protected boolean needSwitchToBluetoothAfterScoActivates = false;
    protected boolean didDeleteConnectionServiceContact = false;

    public interface StateListener {
        void onAudioSettingsChanged();

        void onSignalBarsCountChanged(int i);

        void onStateChanged(int i);
    }

    public abstract void acceptIncomingCall();

    public abstract void declineIncomingCall();

    public abstract void declineIncomingCall(int i, Runnable runnable);

    public abstract long getCallID();

    public abstract CallConnection getConnectionAndStartCall();

    protected abstract Class<? extends Activity> getUIActivityClass();

    public abstract void hangUp();

    public abstract void hangUp(Runnable runnable);

    protected abstract void showNotification();

    protected abstract void startRinging();

    public abstract void startRingtoneAndVibration();

    protected abstract void updateServerConfig();

    public boolean hasEarpiece() {
        CallConnection callConnection;
        if (USE_CONNECTION_SERVICE && (callConnection = this.systemCallConnection) != null && callConnection.getCallAudioState() != null) {
            int routeMask = this.systemCallConnection.getCallAudioState().getSupportedRouteMask();
            return (routeMask & 5) != 0;
        }
        if (((TelephonyManager) getSystemService("phone")).getPhoneType() != 0) {
            return true;
        }
        Boolean bool = this.mHasEarpiece;
        if (bool != null) {
            return bool.booleanValue();
        }
        try {
            AudioManager am = (AudioManager) getSystemService("audio");
            Method method = AudioManager.class.getMethod("getDevicesForStream", Integer.TYPE);
            Field field = AudioManager.class.getField("DEVICE_OUT_EARPIECE");
            int earpieceFlag = field.getInt(null);
            int bitmaskResult = ((Integer) method.invoke(am, 0)).intValue();
            if ((bitmaskResult & earpieceFlag) == earpieceFlag) {
                this.mHasEarpiece = Boolean.TRUE;
            } else {
                this.mHasEarpiece = Boolean.FALSE;
            }
        } catch (Throwable error) {
            if (BuildVars.LOGS_ENABLED) {
                FileLog.e("Error while checking earpiece! ", error);
            }
            this.mHasEarpiece = Boolean.TRUE;
        }
        return this.mHasEarpiece.booleanValue();
    }

    protected int getStatsNetworkType() {
        NetworkInfo networkInfo = this.lastNetInfo;
        if (networkInfo == null || networkInfo.getType() != 0) {
            return 1;
        }
        int netType = this.lastNetInfo.isRoaming() ? 2 : 0;
        return netType;
    }

    public void registerStateListener(StateListener l) {
        this.stateListeners.add(l);
        int i = this.currentState;
        if (i != 0) {
            l.onStateChanged(i);
        }
        int i2 = this.signalBarCount;
        if (i2 != 0) {
            l.onSignalBarsCountChanged(i2);
        }
    }

    public void unregisterStateListener(StateListener l) {
        this.stateListeners.remove(l);
    }

    public void setMicMute(boolean mute) {
        this.micMute = mute;
        VoIPController voIPController = this.controller;
        if (voIPController != null) {
            voIPController.setMicMute(mute);
        }
    }

    public boolean isMicMute() {
        return this.micMute;
    }

    public void toggleSpeakerphoneOrShowRouteSheet(Activity activity) {
        CallConnection callConnection;
        if (isBluetoothHeadsetConnected() && hasEarpiece()) {
            BottomSheet.Builder bldr = new BottomSheet.Builder(activity).setItems(new CharSequence[]{LocaleController.getString("VoipAudioRoutingBluetooth", R.string.VoipAudioRoutingBluetooth), LocaleController.getString("VoipAudioRoutingEarpiece", R.string.VoipAudioRoutingEarpiece), LocaleController.getString("VoipAudioRoutingSpeaker", R.string.VoipAudioRoutingSpeaker)}, new int[]{R.drawable.ic_bluetooth_white_24dp, R.drawable.ic_phone_in_talk_white_24dp, R.drawable.ic_volume_up_white_24dp}, new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.messenger.voip.VoIPBaseService.3
                @Override // android.content.DialogInterface.OnClickListener
                public void onClick(DialogInterface dialog, int which) {
                    AudioManager am = (AudioManager) VoIPBaseService.this.getSystemService("audio");
                    if (VoIPBaseService.getSharedInstance() == null) {
                        return;
                    }
                    if (VoIPBaseService.USE_CONNECTION_SERVICE && VoIPBaseService.this.systemCallConnection != null) {
                        if (which == 0) {
                            VoIPBaseService.this.systemCallConnection.setAudioRoute(2);
                        } else if (which == 1) {
                            VoIPBaseService.this.systemCallConnection.setAudioRoute(5);
                        } else if (which == 2) {
                            VoIPBaseService.this.systemCallConnection.setAudioRoute(8);
                        }
                    } else if (VoIPBaseService.this.audioConfigured && !VoIPBaseService.USE_CONNECTION_SERVICE) {
                        if (which != 0) {
                            if (which == 1) {
                                if (VoIPBaseService.this.bluetoothScoActive) {
                                    am.stopBluetoothSco();
                                }
                                am.setSpeakerphoneOn(false);
                                am.setBluetoothScoOn(false);
                            } else if (which == 2) {
                                if (VoIPBaseService.this.bluetoothScoActive) {
                                    am.stopBluetoothSco();
                                }
                                am.setBluetoothScoOn(false);
                                am.setSpeakerphoneOn(true);
                            }
                        } else if (!VoIPBaseService.this.bluetoothScoActive) {
                            VoIPBaseService.this.needSwitchToBluetoothAfterScoActivates = true;
                            try {
                                am.startBluetoothSco();
                            } catch (Throwable th) {
                            }
                        } else {
                            am.setBluetoothScoOn(true);
                            am.setSpeakerphoneOn(false);
                        }
                        VoIPBaseService.this.updateOutputGainControlState();
                    } else if (which == 0) {
                        VoIPBaseService.this.audioRouteToSet = 2;
                    } else if (which == 1) {
                        VoIPBaseService.this.audioRouteToSet = 0;
                    } else if (which == 2) {
                        VoIPBaseService.this.audioRouteToSet = 1;
                    }
                    for (StateListener l : VoIPBaseService.this.stateListeners) {
                        l.onAudioSettingsChanged();
                    }
                }
            });
            BottomSheet sheet = bldr.create();
            sheet.setBackgroundColor(-13948117);
            sheet.show();
            ViewGroup container = sheet.getSheetContainer();
            for (int i = 0; i < container.getChildCount(); i++) {
                BottomSheet.BottomSheetCell cell = (BottomSheet.BottomSheetCell) container.getChildAt(i);
                cell.setTextColor(-1);
            }
            return;
        }
        if (USE_CONNECTION_SERVICE && (callConnection = this.systemCallConnection) != null && callConnection.getCallAudioState() != null) {
            if (hasEarpiece()) {
                CallConnection callConnection2 = this.systemCallConnection;
                callConnection2.setAudioRoute(callConnection2.getCallAudioState().getRoute() != 8 ? 8 : 5);
            } else {
                CallConnection callConnection3 = this.systemCallConnection;
                callConnection3.setAudioRoute(callConnection3.getCallAudioState().getRoute() == 2 ? 5 : 2);
            }
        } else if (this.audioConfigured && !USE_CONNECTION_SERVICE) {
            AudioManager am = (AudioManager) getSystemService("audio");
            if (hasEarpiece()) {
                am.setSpeakerphoneOn(!am.isSpeakerphoneOn());
            } else {
                am.setBluetoothScoOn(!am.isBluetoothScoOn());
            }
            updateOutputGainControlState();
        } else {
            this.speakerphoneStateToSet = !this.speakerphoneStateToSet;
        }
        for (StateListener l : this.stateListeners) {
            l.onAudioSettingsChanged();
        }
    }

    public boolean isSpeakerphoneOn() {
        CallConnection callConnection;
        if (USE_CONNECTION_SERVICE && (callConnection = this.systemCallConnection) != null && callConnection.getCallAudioState() != null) {
            int route = this.systemCallConnection.getCallAudioState().getRoute();
            if (hasEarpiece()) {
                if (route == 8) {
                    return true;
                }
            } else if (route == 2) {
                return true;
            }
            return false;
        }
        if (this.audioConfigured && !USE_CONNECTION_SERVICE) {
            AudioManager am = (AudioManager) getSystemService("audio");
            return hasEarpiece() ? am.isSpeakerphoneOn() : am.isBluetoothScoOn();
        }
        return this.speakerphoneStateToSet;
    }

    public int getCurrentAudioRoute() {
        if (USE_CONNECTION_SERVICE) {
            CallConnection callConnection = this.systemCallConnection;
            if (callConnection != null && callConnection.getCallAudioState() != null) {
                int route = this.systemCallConnection.getCallAudioState().getRoute();
                if (route != 1) {
                    if (route == 2) {
                        return 2;
                    }
                    if (route != 4) {
                        if (route == 8) {
                            return 1;
                        }
                    }
                }
                return 0;
            }
            return this.audioRouteToSet;
        }
        if (this.audioConfigured) {
            AudioManager am = (AudioManager) getSystemService("audio");
            if (am.isBluetoothScoOn()) {
                return 2;
            }
            return am.isSpeakerphoneOn() ? 1 : 0;
        }
        return this.audioRouteToSet;
    }

    public String getDebugString() {
        return this.controller.getDebugString();
    }

    public long getCallDuration() {
        VoIPController voIPController;
        if (!this.controllerStarted || (voIPController = this.controller) == null) {
            return this.lastKnownDuration;
        }
        long callDuration = voIPController.getCallDuration();
        this.lastKnownDuration = callDuration;
        return callDuration;
    }

    public static VoIPBaseService getSharedInstance() {
        return sharedInstance;
    }

    public void stopRinging() {
        MediaPlayer mediaPlayer = this.ringtonePlayer;
        if (mediaPlayer != null) {
            mediaPlayer.stop();
            this.ringtonePlayer.release();
            this.ringtonePlayer = null;
        }
        Vibrator vibrator = this.vibrator;
        if (vibrator != null) {
            vibrator.cancel();
            this.vibrator = null;
        }
    }

    protected void showNotification(String name, TLRPC.FileLocation photo, Class<? extends Activity> activity) {
        Intent intent = new Intent(this, activity);
        intent.addFlags(805306368);
        Notification.Builder builder = new Notification.Builder(this).setContentTitle(LocaleController.getString("VoipOutgoingCall", R.string.VoipOutgoingCall)).setContentText(name).setSmallIcon(R.id.ic_launcher).setContentIntent(PendingIntent.getActivity(this, 0, intent, 0));
        if (Build.VERSION.SDK_INT >= 16) {
            Intent endIntent = new Intent(this, (Class<?>) VoIPActionsReceiver.class);
            endIntent.setAction(getPackageName() + ".END_CALL");
            builder.addAction(R.drawable.ic_call_end_white_24dp, LocaleController.getString("VoipEndCall", R.string.VoipEndCall), PendingIntent.getBroadcast(this, 0, endIntent, 134217728));
            builder.setPriority(2);
        }
        if (Build.VERSION.SDK_INT >= 17) {
            builder.setShowWhen(false);
        }
        if (Build.VERSION.SDK_INT >= 21) {
            builder.setColor(-13851168);
        }
        if (Build.VERSION.SDK_INT >= 26) {
            NotificationsController.checkOtherNotificationsChannel();
            builder.setChannelId(NotificationsController.OTHER_NOTIFICATIONS_CHANNEL);
        }
        if (photo != null) {
            BitmapDrawable img = ImageLoader.getInstance().getImageFromMemory(photo, null, "50_50");
            if (img != null) {
                builder.setLargeIcon(img.getBitmap());
            } else {
                try {
                    float scaleFactor = 160.0f / AndroidUtilities.dp(50.0f);
                    BitmapFactory.Options options = new BitmapFactory.Options();
                    options.inSampleSize = scaleFactor < 1.0f ? 1 : (int) scaleFactor;
                    Bitmap bitmap = BitmapFactory.decodeFile(FileLoader.getPathToAttach(photo, true).toString(), options);
                    if (bitmap != null) {
                        builder.setLargeIcon(bitmap);
                    }
                } catch (Throwable e) {
                    FileLog.e(e);
                }
            }
        }
        Notification notification = builder.getNotification();
        this.ongoingCallNotification = notification;
        startForeground(ID_ONGOING_CALL_NOTIFICATION, notification);
    }

    protected void startRingtoneAndVibration(int chatID) {
        int vibrate;
        String notificationUri;
        SharedPreferences prefs = MessagesController.getNotificationsSettings(this.currentAccount);
        AudioManager am = (AudioManager) getSystemService("audio");
        boolean needRing = am.getRingerMode() != 0;
        if (needRing) {
            if (!USE_CONNECTION_SERVICE) {
                am.requestAudioFocus(this, 2, 1);
            }
            MediaPlayer mediaPlayer = new MediaPlayer();
            this.ringtonePlayer = mediaPlayer;
            mediaPlayer.setOnPreparedListener(new MediaPlayer.OnPreparedListener() { // from class: im.uwrkaxlmjj.messenger.voip.VoIPBaseService.4
                @Override // android.media.MediaPlayer.OnPreparedListener
                public void onPrepared(MediaPlayer mediaPlayer2) {
                    VoIPBaseService.this.ringtonePlayer.start();
                }
            });
            this.ringtonePlayer.setLooping(true);
            this.ringtonePlayer.setAudioStreamType(2);
            try {
                if (prefs.getBoolean(ContentMetadata.KEY_CUSTOM_PREFIX + chatID, false)) {
                    notificationUri = prefs.getString("ringtone_path_" + chatID, RingtoneManager.getDefaultUri(1).toString());
                } else {
                    notificationUri = prefs.getString("CallsRingtonePath", RingtoneManager.getDefaultUri(1).toString());
                }
                this.ringtonePlayer.setDataSource(this, Uri.parse(notificationUri));
                this.ringtonePlayer.prepareAsync();
            } catch (Exception e) {
                FileLog.e(e);
                MediaPlayer mediaPlayer2 = this.ringtonePlayer;
                if (mediaPlayer2 != null) {
                    mediaPlayer2.release();
                    this.ringtonePlayer = null;
                }
            }
            if (prefs.getBoolean(ContentMetadata.KEY_CUSTOM_PREFIX + chatID, false)) {
                vibrate = prefs.getInt("calls_vibrate_" + chatID, 0);
            } else {
                vibrate = prefs.getInt("vibrate_calls", 0);
            }
            if ((vibrate != 2 && vibrate != 4 && (am.getRingerMode() == 1 || am.getRingerMode() == 2)) || (vibrate == 4 && am.getRingerMode() == 1)) {
                this.vibrator = (Vibrator) getSystemService("vibrator");
                long duration = 700;
                if (vibrate == 1) {
                    duration = 700 / 2;
                } else if (vibrate == 3) {
                    duration = 700 * 2;
                }
                this.vibrator.vibrate(new long[]{0, duration, 500}, 0);
            }
        }
    }

    @Override // android.app.Service
    public void onDestroy() {
        if (BuildVars.LOGS_ENABLED) {
            FileLog.d("=============== VoIPService STOPPING ===============");
        }
        stopForeground(true);
        stopRinging();
        NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.appDidLogout);
        SensorManager sm = (SensorManager) getSystemService("sensor");
        Sensor proximity = sm.getDefaultSensor(8);
        if (proximity != null) {
            sm.unregisterListener(this);
        }
        PowerManager.WakeLock wakeLock = this.proximityWakelock;
        if (wakeLock != null && wakeLock.isHeld()) {
            this.proximityWakelock.release();
        }
        unregisterReceiver(this.receiver);
        Runnable runnable = this.timeoutRunnable;
        if (runnable != null) {
            AndroidUtilities.cancelRunOnUIThread(runnable);
            this.timeoutRunnable = null;
        }
        super.onDestroy();
        sharedInstance = null;
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.voip.VoIPBaseService.5
            @Override // java.lang.Runnable
            public void run() {
                NotificationCenter.getGlobalInstance().postNotificationName(NotificationCenter.didEndedCall, new Object[0]);
            }
        });
        VoIPController voIPController = this.controller;
        if (voIPController != null && this.controllerStarted) {
            this.lastKnownDuration = voIPController.getCallDuration();
            updateStats();
            StatsController.getInstance(this.currentAccount).incrementTotalCallsTime(getStatsNetworkType(), ((int) (this.lastKnownDuration / 1000)) % 5);
            onControllerPreRelease();
            this.controller.release();
            this.controller = null;
        }
        this.cpuWakelock.release();
        AudioManager am = (AudioManager) getSystemService("audio");
        if (!USE_CONNECTION_SERVICE) {
            if (this.isBtHeadsetConnected && !this.playingSound) {
                am.stopBluetoothSco();
                am.setSpeakerphoneOn(false);
            }
            try {
                am.setMode(0);
            } catch (SecurityException x) {
                if (BuildVars.LOGS_ENABLED) {
                    FileLog.e("Error setting audio more to normal", x);
                }
            }
            am.abandonAudioFocus(this);
        }
        am.unregisterMediaButtonEventReceiver(new ComponentName(this, (Class<?>) VoIPMediaButtonReceiver.class));
        if (this.haveAudioFocus) {
            am.abandonAudioFocus(this);
        }
        if (!this.playingSound) {
            this.soundPool.release();
        }
        if (USE_CONNECTION_SERVICE) {
            if (!this.didDeleteConnectionServiceContact) {
                ContactsController.getInstance(this.currentAccount).deleteConnectionServiceContact();
            }
            CallConnection callConnection = this.systemCallConnection;
            if (callConnection != null && !this.playingSound) {
                callConnection.destroy();
            }
        }
        ConnectionsManager.getInstance(this.currentAccount).setAppPaused(true, false);
        VoIPHelper.lastCallTime = System.currentTimeMillis();
    }

    protected void onControllerPreRelease() {
    }

    protected VoIPController createController() {
        return new VoIPController();
    }

    protected void initializeAccountRelatedThings() {
        updateServerConfig();
        NotificationCenter.getInstance(this.currentAccount).addObserver(this, NotificationCenter.appDidLogout);
        ConnectionsManager.getInstance(this.currentAccount).setAppPaused(false, false);
        VoIPController voIPControllerCreateController = createController();
        this.controller = voIPControllerCreateController;
        voIPControllerCreateController.setConnectionStateListener(this);
    }

    @Override // android.app.Service
    public void onCreate() {
        super.onCreate();
        if (BuildVars.LOGS_ENABLED) {
            FileLog.d("=============== VoIPService STARTING ===============");
        }
        AudioManager am = (AudioManager) getSystemService("audio");
        if (Build.VERSION.SDK_INT >= 17 && am.getProperty("android.media.property.OUTPUT_FRAMES_PER_BUFFER") != null) {
            int outFramesPerBuffer = Integer.parseInt(am.getProperty("android.media.property.OUTPUT_FRAMES_PER_BUFFER"));
            VoIPController.setNativeBufferSize(outFramesPerBuffer);
        } else {
            VoIPController.setNativeBufferSize(AudioTrack.getMinBufferSize(48000, 4, 2) / 2);
        }
        try {
            boolean z = true;
            PowerManager.WakeLock wakeLockNewWakeLock = ((PowerManager) getSystemService("power")).newWakeLock(1, "hchat-voip");
            this.cpuWakelock = wakeLockNewWakeLock;
            wakeLockNewWakeLock.acquire();
            this.btAdapter = am.isBluetoothScoAvailableOffCall() ? BluetoothAdapter.getDefaultAdapter() : null;
            IntentFilter filter = new IntentFilter();
            filter.addAction("android.net.conn.CONNECTIVITY_CHANGE");
            if (!USE_CONNECTION_SERVICE) {
                filter.addAction(ACTION_HEADSET_PLUG);
                if (this.btAdapter != null) {
                    filter.addAction("android.bluetooth.headset.profile.action.CONNECTION_STATE_CHANGED");
                    filter.addAction("android.media.ACTION_SCO_AUDIO_STATE_UPDATED");
                }
                filter.addAction("android.intent.action.PHONE_STATE");
            }
            registerReceiver(this.receiver, filter);
            SoundPool soundPool = new SoundPool(1, 0, 0);
            this.soundPool = soundPool;
            this.spConnectingId = soundPool.load(this, R.raw.voip_connecting, 1);
            this.spRingbackID = this.soundPool.load(this, R.raw.voip_ringback, 1);
            this.spFailedID = this.soundPool.load(this, R.raw.voip_failed, 1);
            this.spEndId = this.soundPool.load(this, R.raw.voip_end, 1);
            this.spBusyId = this.soundPool.load(this, R.raw.voip_busy, 1);
            am.registerMediaButtonEventReceiver(new ComponentName(this, (Class<?>) VoIPMediaButtonReceiver.class));
            if (!USE_CONNECTION_SERVICE && this.btAdapter != null && this.btAdapter.isEnabled()) {
                int headsetState = this.btAdapter.getProfileConnectionState(1);
                if (headsetState != 2) {
                    z = false;
                }
                updateBluetoothHeadsetState(z);
                for (StateListener l : this.stateListeners) {
                    l.onAudioSettingsChanged();
                }
            }
        } catch (Exception x) {
            if (BuildVars.LOGS_ENABLED) {
                FileLog.e("error initializing voip controller", x);
            }
            callFailed();
        }
    }

    protected void dispatchStateChanged(int state) {
        CallConnection callConnection;
        if (BuildVars.LOGS_ENABLED) {
            FileLog.d("== Call " + getCallID() + " state changed to " + state + " ==");
        }
        this.currentState = state;
        if (USE_CONNECTION_SERVICE && state == 3 && (callConnection = this.systemCallConnection) != null) {
            callConnection.setActive();
        }
        for (int a = 0; a < this.stateListeners.size(); a++) {
            StateListener l = this.stateListeners.get(a);
            l.onStateChanged(state);
        }
    }

    protected void updateStats() {
        this.controller.getStats(this.stats);
        long wifiSentDiff = this.stats.bytesSentWifi - this.prevStats.bytesSentWifi;
        long wifiRecvdDiff = this.stats.bytesRecvdWifi - this.prevStats.bytesRecvdWifi;
        long mobileSentDiff = this.stats.bytesSentMobile - this.prevStats.bytesSentMobile;
        long mobileRecvdDiff = this.stats.bytesRecvdMobile - this.prevStats.bytesRecvdMobile;
        VoIPController.Stats tmp = this.stats;
        this.stats = this.prevStats;
        this.prevStats = tmp;
        if (wifiSentDiff > 0) {
            StatsController.getInstance(this.currentAccount).incrementSentBytesCount(1, 0, wifiSentDiff);
        }
        if (wifiRecvdDiff > 0) {
            StatsController.getInstance(this.currentAccount).incrementReceivedBytesCount(1, 0, wifiRecvdDiff);
        }
        if (mobileSentDiff > 0) {
            StatsController statsController = StatsController.getInstance(this.currentAccount);
            NetworkInfo networkInfo = this.lastNetInfo;
            statsController.incrementSentBytesCount((networkInfo == null || !networkInfo.isRoaming()) ? 0 : 2, 0, mobileSentDiff);
        }
        if (mobileRecvdDiff > 0) {
            StatsController statsController2 = StatsController.getInstance(this.currentAccount);
            NetworkInfo networkInfo2 = this.lastNetInfo;
            statsController2.incrementReceivedBytesCount((networkInfo2 == null || !networkInfo2.isRoaming()) ? 0 : 2, 0, mobileRecvdDiff);
        }
    }

    protected void configureDeviceForCall() {
        this.needPlayEndSound = true;
        AudioManager am = (AudioManager) getSystemService("audio");
        if (!USE_CONNECTION_SERVICE) {
            am.setMode(3);
            am.requestAudioFocus(this, 0, 1);
            if (isBluetoothHeadsetConnected() && hasEarpiece()) {
                int i = this.audioRouteToSet;
                if (i != 0) {
                    if (i == 1) {
                        am.setBluetoothScoOn(false);
                        am.setSpeakerphoneOn(true);
                    } else if (i == 2) {
                        if (!this.bluetoothScoActive) {
                            this.needSwitchToBluetoothAfterScoActivates = true;
                            try {
                                am.startBluetoothSco();
                            } catch (Throwable th) {
                            }
                        } else {
                            am.setBluetoothScoOn(true);
                            am.setSpeakerphoneOn(false);
                        }
                    }
                } else {
                    am.setBluetoothScoOn(false);
                    am.setSpeakerphoneOn(false);
                }
            } else if (isBluetoothHeadsetConnected()) {
                am.setBluetoothScoOn(this.speakerphoneStateToSet);
            } else {
                am.setSpeakerphoneOn(this.speakerphoneStateToSet);
            }
        }
        updateOutputGainControlState();
        this.audioConfigured = true;
        SensorManager sm = (SensorManager) getSystemService("sensor");
        Sensor proximity = sm.getDefaultSensor(8);
        if (proximity != null) {
            try {
                this.proximityWakelock = ((PowerManager) getSystemService("power")).newWakeLock(32, "hchat-voip-prx");
                sm.registerListener(this, proximity, 3);
            } catch (Exception x) {
                if (BuildVars.LOGS_ENABLED) {
                    FileLog.e("Error initializing proximity sensor", x);
                }
            }
        }
    }

    @Override // android.hardware.SensorEventListener
    public void onSensorChanged(SensorEvent event) {
        if (event.sensor.getType() == 8) {
            AudioManager am = (AudioManager) getSystemService("audio");
            if (this.isHeadsetPlugged || am.isSpeakerphoneOn()) {
                return;
            }
            if (isBluetoothHeadsetConnected() && am.isBluetoothScoOn()) {
                return;
            }
            boolean newIsNear = event.values[0] < Math.min(event.sensor.getMaximumRange(), 3.0f);
            if (newIsNear != this.isProximityNear) {
                if (BuildVars.LOGS_ENABLED) {
                    FileLog.d("proximity " + newIsNear);
                }
                this.isProximityNear = newIsNear;
                try {
                    if (newIsNear) {
                        this.proximityWakelock.acquire();
                    } else {
                        this.proximityWakelock.release(1);
                    }
                } catch (Exception x) {
                    FileLog.e(x);
                }
            }
        }
    }

    @Override // android.hardware.SensorEventListener
    public void onAccuracyChanged(Sensor sensor, int accuracy) {
    }

    public boolean isBluetoothHeadsetConnected() {
        CallConnection callConnection;
        if (!USE_CONNECTION_SERVICE || (callConnection = this.systemCallConnection) == null || callConnection.getCallAudioState() == null) {
            return this.isBtHeadsetConnected;
        }
        return (this.systemCallConnection.getCallAudioState().getSupportedRouteMask() & 2) != 0;
    }

    @Override // android.media.AudioManager.OnAudioFocusChangeListener
    public void onAudioFocusChange(int focusChange) {
        if (focusChange == 1) {
            this.haveAudioFocus = true;
        } else {
            this.haveAudioFocus = false;
        }
    }

    protected void updateBluetoothHeadsetState(boolean connected) {
        if (connected == this.isBtHeadsetConnected) {
            return;
        }
        if (BuildVars.LOGS_ENABLED) {
            FileLog.d("updateBluetoothHeadsetState: " + connected);
        }
        this.isBtHeadsetConnected = connected;
        final AudioManager am = (AudioManager) getSystemService("audio");
        if (connected && !isRinging() && this.currentState != 0) {
            if (this.bluetoothScoActive) {
                if (BuildVars.LOGS_ENABLED) {
                    FileLog.d("SCO already active, setting audio routing");
                }
                am.setSpeakerphoneOn(false);
                am.setBluetoothScoOn(true);
            } else {
                if (BuildVars.LOGS_ENABLED) {
                    FileLog.d("startBluetoothSco");
                }
                this.needSwitchToBluetoothAfterScoActivates = true;
                AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.voip.VoIPBaseService.6
                    @Override // java.lang.Runnable
                    public void run() {
                        try {
                            am.startBluetoothSco();
                        } catch (Throwable th) {
                        }
                    }
                }, 500L);
            }
        } else {
            this.bluetoothScoActive = false;
        }
        for (StateListener l : this.stateListeners) {
            l.onAudioSettingsChanged();
        }
    }

    public int getLastError() {
        return this.lastError;
    }

    public int getCallState() {
        return this.currentState;
    }

    protected void updateNetworkType() {
        ConnectivityManager cm = (ConnectivityManager) getSystemService("connectivity");
        NetworkInfo info = cm.getActiveNetworkInfo();
        this.lastNetInfo = info;
        int type = 0;
        if (info != null) {
            int type2 = info.getType();
            if (type2 == 0) {
                switch (info.getSubtype()) {
                    case 1:
                        type = 1;
                        break;
                    case 2:
                    case 7:
                        type = 2;
                        break;
                    case 3:
                    case 5:
                        type = 3;
                        break;
                    case 4:
                    case 11:
                    case 14:
                    default:
                        type = 11;
                        break;
                    case 6:
                    case 8:
                    case 9:
                    case 10:
                    case 12:
                    case 15:
                        type = 4;
                        break;
                    case 13:
                        type = 5;
                        break;
                }
            } else if (type2 == 1) {
                type = 6;
            } else if (type2 == 9) {
                type = 7;
            }
        }
        VoIPController voIPController = this.controller;
        if (voIPController != null) {
            voIPController.setNetworkType(type);
        }
    }

    protected void callFailed() {
        VoIPController voIPController = this.controller;
        callFailed((voIPController == null || !this.controllerStarted) ? 0 : voIPController.getLastError());
    }

    protected Bitmap getRoundAvatarBitmap(TLObject userOrChat) {
        AvatarDrawable placeholder;
        Bitmap bitmap = null;
        if (userOrChat instanceof TLRPC.User) {
            TLRPC.User user = (TLRPC.User) userOrChat;
            if (user.photo != null && user.photo.photo_small != null) {
                BitmapDrawable img = ImageLoader.getInstance().getImageFromMemory(user.photo.photo_small, null, "50_50");
                if (img != null) {
                    bitmap = img.getBitmap().copy(Bitmap.Config.ARGB_8888, true);
                } else {
                    try {
                        BitmapFactory.Options opts = new BitmapFactory.Options();
                        opts.inMutable = true;
                        bitmap = BitmapFactory.decodeFile(FileLoader.getPathToAttach(user.photo.photo_small, true).toString(), opts);
                    } catch (Throwable e) {
                        FileLog.e(e);
                    }
                }
            }
        } else {
            TLRPC.Chat chat = (TLRPC.Chat) userOrChat;
            if (chat.photo != null && chat.photo.photo_small != null) {
                BitmapDrawable img2 = ImageLoader.getInstance().getImageFromMemory(chat.photo.photo_small, null, "50_50");
                if (img2 != null) {
                    bitmap = img2.getBitmap().copy(Bitmap.Config.ARGB_8888, true);
                } else {
                    try {
                        BitmapFactory.Options opts2 = new BitmapFactory.Options();
                        opts2.inMutable = true;
                        bitmap = BitmapFactory.decodeFile(FileLoader.getPathToAttach(chat.photo.photo_small, true).toString(), opts2);
                    } catch (Throwable e2) {
                        FileLog.e(e2);
                    }
                }
            }
        }
        if (bitmap == null) {
            Theme.createDialogsResources(this);
            if (userOrChat instanceof TLRPC.User) {
                placeholder = new AvatarDrawable((TLRPC.User) userOrChat);
            } else {
                placeholder = new AvatarDrawable((TLRPC.Chat) userOrChat);
            }
            bitmap = Bitmap.createBitmap(AndroidUtilities.dp(42.0f), AndroidUtilities.dp(42.0f), Bitmap.Config.ARGB_8888);
            placeholder.setBounds(0, 0, bitmap.getWidth(), bitmap.getHeight());
            placeholder.draw(new Canvas(bitmap));
        }
        Canvas canvas = new Canvas(bitmap);
        Path circlePath = new Path();
        circlePath.addCircle(bitmap.getWidth() / 2, bitmap.getHeight() / 2, bitmap.getWidth() / 2, Path.Direction.CW);
        circlePath.toggleInverseFillType();
        Paint paint = new Paint(1);
        paint.setXfermode(new PorterDuffXfermode(PorterDuff.Mode.CLEAR));
        canvas.drawPath(circlePath, paint);
        return bitmap;
    }

    protected void showIncomingNotification(String name, CharSequence subText, TLObject userOrChat, List<TLRPC.User> groupUsers, int additionalMemberCount, Class<? extends Activity> activityOnClick) {
        int i;
        CharSequence answerTitle;
        int i2;
        boolean subtitleVisible;
        boolean subtitleVisible2;
        Intent intent = new Intent(this, activityOnClick);
        intent.addFlags(805306368);
        Notification.Builder builder = new Notification.Builder(this).setContentTitle(LocaleController.getString("VoipInCallBranding", R.string.VoipInCallBranding)).setContentText(name).setSmallIcon(R.id.ic_launcher).setSubText(subText).setContentIntent(PendingIntent.getActivity(this, 0, intent, 0));
        Uri soundProviderUri = Uri.parse("content://singansfg.uwrkaxlmjj.sdancsuhsfj.call_sound_provider/start_ringing");
        if (Build.VERSION.SDK_INT >= 26) {
            SharedPreferences nprefs = MessagesController.getGlobalNotificationsSettings();
            int chanIndex = nprefs.getInt("calls_notification_channel", 0);
            NotificationManager nm = (NotificationManager) getSystemService("notification");
            NotificationChannel oldChannel = nm.getNotificationChannel("incoming_calls" + chanIndex);
            if (oldChannel != null) {
                nm.deleteNotificationChannel(oldChannel.getId());
            }
            NotificationChannel existingChannel = nm.getNotificationChannel("incoming_calls2" + chanIndex);
            boolean needCreate = true;
            if (existingChannel != null) {
                if (existingChannel.getImportance() < 4 || !soundProviderUri.equals(existingChannel.getSound()) || existingChannel.getVibrationPattern() != null || existingChannel.shouldVibrate()) {
                    if (BuildVars.LOGS_ENABLED) {
                        FileLog.d("User messed up the notification channel; deleting it and creating a proper one");
                    }
                    nm.deleteNotificationChannel("incoming_calls2" + chanIndex);
                    chanIndex++;
                    nprefs.edit().putInt("calls_notification_channel", chanIndex).commit();
                } else {
                    needCreate = false;
                }
            }
            if (needCreate) {
                AudioAttributes attrs = new AudioAttributes.Builder().setUsage(6).build();
                NotificationChannel chan = new NotificationChannel("incoming_calls2" + chanIndex, LocaleController.getString("IncomingCalls", R.string.IncomingCalls), 4);
                chan.setSound(soundProviderUri, attrs);
                chan.enableVibration(false);
                chan.enableLights(false);
                nm.createNotificationChannel(chan);
            }
            builder.setChannelId("incoming_calls2" + chanIndex);
        } else if (Build.VERSION.SDK_INT >= 21) {
            builder.setSound(soundProviderUri, 2);
        }
        Intent endIntent = new Intent(this, (Class<?>) VoIPActionsReceiver.class);
        endIntent.setAction(getPackageName() + ".DECLINE_CALL");
        endIntent.putExtra("call_id", getCallID());
        CharSequence endTitle = LocaleController.getString("VoipDeclineCall", R.string.VoipDeclineCall);
        if (Build.VERSION.SDK_INT < 24) {
            i = 0;
        } else {
            endTitle = new SpannableString(endTitle);
            i = 0;
            ((SpannableString) endTitle).setSpan(new ForegroundColorSpan(-769226), 0, endTitle.length(), 0);
        }
        PendingIntent endPendingIntent = PendingIntent.getBroadcast(this, i, endIntent, C.ENCODING_PCM_MU_LAW);
        builder.addAction(R.drawable.ic_call_end_white_24dp, endTitle, endPendingIntent);
        Intent answerIntent = new Intent(this, (Class<?>) VoIPActionsReceiver.class);
        answerIntent.setAction(getPackageName() + ".ANSWER_CALL");
        answerIntent.putExtra("call_id", getCallID());
        CharSequence answerTitle2 = LocaleController.getString("VoipAnswerCall", R.string.VoipAnswerCall);
        if (Build.VERSION.SDK_INT < 24) {
            answerTitle = answerTitle2;
            i2 = 0;
        } else {
            CharSequence answerTitle3 = new SpannableString(answerTitle2);
            i2 = 0;
            ((SpannableString) answerTitle3).setSpan(new ForegroundColorSpan(-16733696), 0, answerTitle3.length(), 0);
            answerTitle = answerTitle3;
        }
        PendingIntent answerPendingIntent = PendingIntent.getBroadcast(this, i2, answerIntent, C.ENCODING_PCM_MU_LAW);
        builder.addAction(R.drawable.ic_call, answerTitle, answerPendingIntent);
        builder.setPriority(2);
        if (Build.VERSION.SDK_INT >= 17) {
            builder.setShowWhen(false);
        }
        if (Build.VERSION.SDK_INT >= 21) {
            builder.setColor(-13851168);
            builder.setVibrate(new long[0]);
            builder.setCategory(NotificationCompat.CATEGORY_CALL);
            builder.setFullScreenIntent(PendingIntent.getActivity(this, 0, intent, 0), true);
            if (userOrChat instanceof TLRPC.User) {
                TLRPC.User user = (TLRPC.User) userOrChat;
                if (!TextUtils.isEmpty(user.phone)) {
                    builder.addPerson("tel:" + user.phone);
                }
            }
        }
        Notification incomingNotification = builder.getNotification();
        if (Build.VERSION.SDK_INT >= 21) {
            RemoteViews customView = new RemoteViews(getPackageName(), LocaleController.isRTL ? R.layout.call_notification_rtl : R.layout.call_notification);
            customView.setTextViewText(R.attr.name, name);
            if (TextUtils.isEmpty(subText)) {
                customView.setViewVisibility(R.attr.subtitle, 8);
                if (UserConfig.getActivatedAccountsCount() > 1) {
                    TLRPC.User self = UserConfig.getInstance(this.currentAccount).getCurrentUser();
                    subtitleVisible2 = false;
                    customView.setTextViewText(R.attr.title, LocaleController.formatString("VoipInCallBrandingWithName", R.string.VoipInCallBrandingWithName, ContactsController.formatName(self.first_name, self.last_name)));
                } else {
                    subtitleVisible2 = false;
                    customView.setTextViewText(R.attr.title, LocaleController.getString("VoipInCallBranding", R.string.VoipInCallBranding));
                }
            } else {
                if (UserConfig.getActivatedAccountsCount() > 1) {
                    TLRPC.User self2 = UserConfig.getInstance(this.currentAccount).getCurrentUser();
                    customView.setTextViewText(R.attr.subtitle, LocaleController.formatString("VoipAnsweringAsAccount", R.string.VoipAnsweringAsAccount, ContactsController.formatName(self2.first_name, self2.last_name)));
                    subtitleVisible = true;
                } else {
                    customView.setViewVisibility(R.attr.subtitle, 8);
                    subtitleVisible = false;
                }
                customView.setTextViewText(R.attr.title, subText);
            }
            Bitmap avatar = getRoundAvatarBitmap(userOrChat);
            customView.setTextViewText(R.attr.answer_text, LocaleController.getString("VoipAnswerCall", R.string.VoipAnswerCall));
            customView.setTextViewText(R.attr.decline_text, LocaleController.getString("VoipDeclineCall", R.string.VoipDeclineCall));
            customView.setImageViewBitmap(R.attr.photo, avatar);
            customView.setOnClickPendingIntent(R.attr.answer_btn, answerPendingIntent);
            customView.setOnClickPendingIntent(R.attr.decline_btn, endPendingIntent);
            builder.setLargeIcon(avatar);
            incomingNotification.bigContentView = customView;
            incomingNotification.headsUpContentView = customView;
        }
        startForeground(ID_INCOMING_CALL_NOTIFICATION, incomingNotification);
    }

    protected void callFailed(int errorCode) {
        CallConnection callConnection;
        SoundPool soundPool;
        try {
            throw new Exception("Call " + getCallID() + " failed with error code " + errorCode);
        } catch (Exception x) {
            FileLog.e(x);
            this.lastError = errorCode;
            dispatchStateChanged(4);
            if (errorCode != -3 && (soundPool = this.soundPool) != null) {
                this.playingSound = true;
                soundPool.play(this.spFailedID, 1.0f, 1.0f, 0, 0, 1.0f);
                AndroidUtilities.runOnUIThread(this.afterSoundRunnable, 1000L);
            }
            if (USE_CONNECTION_SERVICE && (callConnection = this.systemCallConnection) != null) {
                callConnection.setDisconnected(new DisconnectCause(1));
                this.systemCallConnection.destroy();
                this.systemCallConnection = null;
            }
            stopSelf();
        }
    }

    void callFailedFromConnectionService() {
        if (this.isOutgoing) {
            callFailed(-5);
        } else {
            hangUp();
        }
    }

    @Override // im.uwrkaxlmjj.messenger.voip.VoIPController.ConnectionStateListener
    public void onConnectionStateChanged(int newState) {
        if (newState == 4) {
            callFailed();
            return;
        }
        if (newState == 3) {
            Runnable runnable = this.connectingSoundRunnable;
            if (runnable != null) {
                AndroidUtilities.cancelRunOnUIThread(runnable);
                this.connectingSoundRunnable = null;
            }
            int i = this.spPlayID;
            if (i != 0) {
                this.soundPool.stop(i);
                this.spPlayID = 0;
            }
            if (!this.wasEstablished) {
                this.wasEstablished = true;
                if (!this.isProximityNear) {
                    Vibrator vibrator = (Vibrator) getSystemService("vibrator");
                    if (vibrator.hasVibrator()) {
                        vibrator.vibrate(100L);
                    }
                }
                AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.messenger.voip.VoIPBaseService.7
                    @Override // java.lang.Runnable
                    public void run() {
                        if (VoIPBaseService.this.controller == null) {
                            return;
                        }
                        int netType = VoIPBaseService.this.getStatsNetworkType();
                        StatsController.getInstance(VoIPBaseService.this.currentAccount).incrementTotalCallsTime(netType, 5);
                        AndroidUtilities.runOnUIThread(this, DefaultRenderersFactory.DEFAULT_ALLOWED_VIDEO_JOINING_TIME_MS);
                    }
                }, DefaultRenderersFactory.DEFAULT_ALLOWED_VIDEO_JOINING_TIME_MS);
                if (this.isOutgoing) {
                    StatsController.getInstance(this.currentAccount).incrementSentItemsCount(getStatsNetworkType(), 0, 1);
                } else {
                    StatsController.getInstance(this.currentAccount).incrementReceivedItemsCount(getStatsNetworkType(), 0, 1);
                }
            }
        }
        if (newState == 5) {
            int i2 = this.spPlayID;
            if (i2 != 0) {
                this.soundPool.stop(i2);
            }
            this.spPlayID = this.soundPool.play(this.spConnectingId, 1.0f, 1.0f, 0, -1, 1.0f);
        }
        dispatchStateChanged(newState);
    }

    @Override // im.uwrkaxlmjj.messenger.voip.VoIPController.ConnectionStateListener
    public void onSignalBarCountChanged(int newCount) {
        this.signalBarCount = newCount;
        for (int a = 0; a < this.stateListeners.size(); a++) {
            StateListener l = this.stateListeners.get(a);
            l.onSignalBarsCountChanged(newCount);
        }
    }

    protected void callEnded() {
        if (BuildVars.LOGS_ENABLED) {
            FileLog.d("Call " + getCallID() + " ended");
        }
        dispatchStateChanged(11);
        if (this.needPlayEndSound) {
            this.playingSound = true;
            this.soundPool.play(this.spEndId, 1.0f, 1.0f, 0, 0, 1.0f);
            AndroidUtilities.runOnUIThread(this.afterSoundRunnable, 700L);
        }
        Runnable runnable = this.timeoutRunnable;
        if (runnable != null) {
            AndroidUtilities.cancelRunOnUIThread(runnable);
            this.timeoutRunnable = null;
        }
        endConnectionServiceCall(this.needPlayEndSound ? 700L : 0L);
        stopSelf();
    }

    protected void endConnectionServiceCall(long delay) {
        if (USE_CONNECTION_SERVICE) {
            Runnable r = new Runnable() { // from class: im.uwrkaxlmjj.messenger.voip.VoIPBaseService.8
                @Override // java.lang.Runnable
                public void run() {
                    if (VoIPBaseService.this.systemCallConnection != null) {
                        int i = VoIPBaseService.this.callDiscardReason;
                        if (i == 1) {
                            VoIPBaseService.this.systemCallConnection.setDisconnected(new DisconnectCause(VoIPBaseService.this.isOutgoing ? 2 : 6));
                        } else if (i != 2) {
                            if (i == 3) {
                                VoIPBaseService.this.systemCallConnection.setDisconnected(new DisconnectCause(VoIPBaseService.this.isOutgoing ? 4 : 5));
                            } else if (i == 4) {
                                VoIPBaseService.this.systemCallConnection.setDisconnected(new DisconnectCause(7));
                            } else {
                                VoIPBaseService.this.systemCallConnection.setDisconnected(new DisconnectCause(3));
                            }
                        } else {
                            VoIPBaseService.this.systemCallConnection.setDisconnected(new DisconnectCause(1));
                        }
                        VoIPBaseService.this.systemCallConnection.destroy();
                        VoIPBaseService.this.systemCallConnection = null;
                    }
                }
            };
            if (delay > 0) {
                AndroidUtilities.runOnUIThread(r, delay);
            } else {
                r.run();
            }
        }
    }

    public boolean isOutgoing() {
        return this.isOutgoing;
    }

    public void handleNotificationAction(Intent intent) {
        if ((getPackageName() + ".END_CALL").equals(intent.getAction())) {
            stopForeground(true);
            hangUp();
            return;
        }
        if ((getPackageName() + ".DECLINE_CALL").equals(intent.getAction())) {
            stopForeground(true);
            declineIncomingCall(4, null);
            return;
        }
        if ((getPackageName() + ".ANSWER_CALL").equals(intent.getAction())) {
            acceptIncomingCallFromNotification();
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void acceptIncomingCallFromNotification() {
        showNotification();
        if (Build.VERSION.SDK_INT >= 23 && checkSelfPermission("android.permission.RECORD_AUDIO") != 0) {
            try {
                PendingIntent.getActivity(this, 0, new Intent(this, (Class<?>) VoIPPermissionActivity.class).addFlags(C.ENCODING_PCM_MU_LAW), 0).send();
                return;
            } catch (Exception x) {
                if (BuildVars.LOGS_ENABLED) {
                    FileLog.e("Error starting permission activity", x);
                    return;
                }
                return;
            }
        }
        acceptIncomingCall();
        try {
            PendingIntent.getActivity(this, 0, new Intent(this, getUIActivityClass()).addFlags(805306368), 0).send();
        } catch (Exception x2) {
            if (BuildVars.LOGS_ENABLED) {
                FileLog.e("Error starting incall activity", x2);
            }
        }
    }

    public void updateOutputGainControlState() {
        if (this.controller == null || !this.controllerStarted) {
            return;
        }
        if (!USE_CONNECTION_SERVICE) {
            AudioManager am = (AudioManager) getSystemService("audio");
            this.controller.setAudioOutputGainControlEnabled((!hasEarpiece() || am.isSpeakerphoneOn() || am.isBluetoothScoOn() || this.isHeadsetPlugged) ? false : true);
            VoIPController voIPController = this.controller;
            if (!this.isHeadsetPlugged && (!hasEarpiece() || am.isSpeakerphoneOn() || am.isBluetoothScoOn() || this.isHeadsetPlugged)) {
                i = 1;
            }
            voIPController.setEchoCancellationStrength(i);
            return;
        }
        boolean isEarpiece = this.systemCallConnection.getCallAudioState().getRoute() == 1;
        this.controller.setAudioOutputGainControlEnabled(isEarpiece);
        this.controller.setEchoCancellationStrength(isEarpiece ? 0 : 1);
    }

    public int getAccount() {
        return this.currentAccount;
    }

    @Override // im.uwrkaxlmjj.messenger.NotificationCenter.NotificationCenterDelegate
    public void didReceivedNotification(int id, int account, Object... args) {
        if (id == NotificationCenter.appDidLogout) {
            callEnded();
        }
    }

    public static boolean isAnyKindOfCallActive() {
        return (VoIPService.getSharedInstance() == null || VoIPService.getSharedInstance().getCallState() == 15) ? false : true;
    }

    protected boolean isFinished() {
        int i = this.currentState;
        return i == 11 || i == 4;
    }

    protected boolean isRinging() {
        return false;
    }

    protected PhoneAccountHandle addAccountToTelecomManager() {
        TelecomManager tm = (TelecomManager) getSystemService("telecom");
        TLRPC.User self = UserConfig.getInstance(this.currentAccount).getCurrentUser();
        PhoneAccountHandle handle = new PhoneAccountHandle(new ComponentName(this, (Class<?>) AppConnectionService.class), "" + self.id);
        PhoneAccount account = new PhoneAccount.Builder(handle, ContactsController.formatName(self.first_name, self.last_name)).setCapabilities(2048).setIcon(Icon.createWithResource(this, R.id.ic_logo)).setHighlightColor(-13851168).addSupportedUriScheme("sip").build();
        tm.registerPhoneAccount(account);
        return handle;
    }

    private static boolean isDeviceCompatibleWithConnectionServiceAPI() {
        if (Build.VERSION.SDK_INT < 26) {
            return false;
        }
        return "angler".equals(Build.PRODUCT) || "bullhead".equals(Build.PRODUCT) || "sailfish".equals(Build.PRODUCT) || "marlin".equals(Build.PRODUCT) || "walleye".equals(Build.PRODUCT) || "taimen".equals(Build.PRODUCT) || "blueline".equals(Build.PRODUCT) || "crosshatch".equals(Build.PRODUCT) || MessagesController.getGlobalMainSettings().getBoolean("dbg_force_connection_service", false);
    }

    public class CallConnection extends Connection {
        public CallConnection() {
            setConnectionProperties(128);
            setAudioModeIsVoip(true);
        }

        @Override // android.telecom.Connection
        public void onCallAudioStateChanged(CallAudioState state) {
            if (BuildVars.LOGS_ENABLED) {
                FileLog.d("ConnectionService call audio state changed: " + state);
            }
            for (StateListener l : VoIPBaseService.this.stateListeners) {
                l.onAudioSettingsChanged();
            }
        }

        @Override // android.telecom.Connection
        public void onDisconnect() {
            if (BuildVars.LOGS_ENABLED) {
                FileLog.d("ConnectionService onDisconnect");
            }
            setDisconnected(new DisconnectCause(2));
            destroy();
            VoIPBaseService.this.systemCallConnection = null;
            VoIPBaseService.this.hangUp();
        }

        @Override // android.telecom.Connection
        public void onAnswer() {
            VoIPBaseService.this.acceptIncomingCallFromNotification();
        }

        @Override // android.telecom.Connection
        public void onReject() {
            VoIPBaseService.this.needPlayEndSound = false;
            VoIPBaseService.this.declineIncomingCall(1, null);
        }

        @Override // android.telecom.Connection
        public void onShowIncomingCallUi() {
            VoIPBaseService.this.startRinging();
        }

        @Override // android.telecom.Connection
        public void onStateChanged(int state) {
            super.onStateChanged(state);
            if (BuildVars.LOGS_ENABLED) {
                FileLog.d("ConnectionService onStateChanged " + stateToString(state));
            }
            if (state == 4) {
                ContactsController.getInstance(VoIPBaseService.this.currentAccount).deleteConnectionServiceContact();
                VoIPBaseService.this.didDeleteConnectionServiceContact = true;
            }
        }

        @Override // android.telecom.Connection
        public void onCallEvent(String event, Bundle extras) {
            super.onCallEvent(event, extras);
            if (BuildVars.LOGS_ENABLED) {
                FileLog.d("ConnectionService onCallEvent " + event);
            }
        }

        @Override // android.telecom.Connection
        public void onSilence() {
            if (BuildVars.LOGS_ENABLED) {
                FileLog.d("onSlience");
            }
            VoIPBaseService.this.stopRinging();
        }
    }
}
