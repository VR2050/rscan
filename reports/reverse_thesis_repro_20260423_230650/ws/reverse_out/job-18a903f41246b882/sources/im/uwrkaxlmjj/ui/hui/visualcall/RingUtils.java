package im.uwrkaxlmjj.ui.hui.visualcall;

import android.content.Context;
import android.database.ContentObserver;
import android.media.AudioManager;
import android.media.MediaPlayer;
import android.media.SoundPool;
import android.net.Uri;
import android.os.Handler;
import android.os.Vibrator;
import android.provider.Settings;
import com.socks.library.KLog;
import im.uwrkaxlmjj.messenger.ApplicationLoader;
import im.uwrkaxlmjj.messenger.FileLog;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class RingUtils {
    private static SettingsContentObserver mSettingsContentObserver;
    private static MediaPlayer ringtonePlayer;
    private static SoundPool soundPool;
    private static int spConnectingId;
    private static Vibrator vibrator;
    private static byte bytSoundPlaying = 0;
    private static byte mbytLast = -1;

    public static void playRingBySoundPool(Context context) {
        if (getSystemRingMode(context) == 2 && soundPool == null) {
            mbytLast = (byte) -1;
            bytSoundPlaying = (byte) 1;
            AudioManager audioManager = (AudioManager) context.getSystemService("audio");
            if (audioManager != null) {
                int iMaxVolume = audioManager.getStreamMaxVolume(3);
                int iCurrVolume = audioManager.getStreamVolume(3);
                if (iCurrVolume < (iMaxVolume / 2) + 1) {
                    audioManager.setStreamVolume(3, (iMaxVolume / 2) + 1, 4);
                }
            }
            SoundPool soundPool2 = new SoundPool(3, 3, 0);
            soundPool = soundPool2;
            spConnectingId = soundPool2.load(context, R.raw.visual_call_receive, 1);
            soundPool.setOnLoadCompleteListener(new SoundPool.OnLoadCompleteListener() { // from class: im.uwrkaxlmjj.ui.hui.visualcall.-$$Lambda$RingUtils$s-xFKtP6RM5PYAeliTekiIw1OLU
                @Override // android.media.SoundPool.OnLoadCompleteListener
                public final void onLoadComplete(SoundPool soundPool3, int i, int i2) {
                    soundPool3.play(RingUtils.spConnectingId, 1.0f, 1.0f, 1, -1, 1.0f);
                }
            });
        }
    }

    public static void playRingByMediaPlayer(Context context) {
        if (getSystemRingMode(context) == 2 && ringtonePlayer == null && bytSoundPlaying == 0) {
            MediaPlayer mediaPlayer = new MediaPlayer();
            ringtonePlayer = mediaPlayer;
            mediaPlayer.setOnPreparedListener(new MediaPlayer.OnPreparedListener() { // from class: im.uwrkaxlmjj.ui.hui.visualcall.RingUtils.1
                @Override // android.media.MediaPlayer.OnPreparedListener
                public void onPrepared(MediaPlayer mediaPlayer2) {
                    RingUtils.ringtonePlayer.start();
                }
            });
            ringtonePlayer.setLooping(true);
            ringtonePlayer.setAudioStreamType(2);
            try {
                ringtonePlayer.setDataSource(context, Uri.parse("android.resource://" + context.getPackageName() + "/" + R.raw.visual_call_receive));
                ringtonePlayer.prepareAsync();
            } catch (Exception e) {
                FileLog.e(e);
                MediaPlayer mediaPlayer2 = ringtonePlayer;
                if (mediaPlayer2 != null) {
                    mediaPlayer2.release();
                    ringtonePlayer = null;
                }
            }
            playVibrator(context);
        }
    }

    private static void playVibrator(Context context) {
        if (vibrator == null) {
            vibrator = (Vibrator) context.getSystemService("vibrator");
        }
        long duration = 700 * 2;
        Vibrator vibrator2 = vibrator;
        if (vibrator2 != null) {
            vibrator2.vibrate(new long[]{0, duration, 1000}, 0);
        }
    }

    public static void stopPlayVibrator() {
        Vibrator vibrator2 = vibrator;
        if (vibrator2 != null) {
            vibrator2.cancel();
            vibrator = null;
        }
    }

    public static void stopMediaPlayerRing() {
        MediaPlayer mediaPlayer = ringtonePlayer;
        if (mediaPlayer != null) {
            mediaPlayer.stop();
            ringtonePlayer.release();
            ringtonePlayer = null;
        }
        Vibrator vibrator2 = vibrator;
        if (vibrator2 != null) {
            vibrator2.cancel();
            vibrator = null;
        }
    }

    public static void stopSoundPoolRing() {
        SoundPool soundPool2;
        int i = spConnectingId;
        if (i != 0 && (soundPool2 = soundPool) != null) {
            soundPool2.stop(i);
            spConnectingId = 0;
            soundPool.release();
            soundPool = null;
            bytSoundPlaying = (byte) 0;
        }
        Vibrator vibrator2 = vibrator;
        if (vibrator2 != null) {
            vibrator2.cancel();
            vibrator = null;
        }
    }

    private static int getSystemRingMode(Context context) {
        AudioManager audioManager = (AudioManager) context.getSystemService("audio");
        if (audioManager != null) {
            return audioManager.getRingerMode();
        }
        return 2;
    }

    private static void registerVolumeChangeReceiver(Context context) {
        mSettingsContentObserver = new SettingsContentObserver(context, new Handler());
        ApplicationLoader.applicationContext.getContentResolver().registerContentObserver(Settings.System.CONTENT_URI, true, mSettingsContentObserver);
    }

    private static void unregisterVolumeChangeReceiver() {
        ApplicationLoader.applicationContext.getContentResolver().unregisterContentObserver(mSettingsContentObserver);
    }

    public static class SettingsContentObserver extends ContentObserver {
        Context context;

        public SettingsContentObserver(Context c, Handler handler) {
            super(handler);
            this.context = c;
        }

        @Override // android.database.ContentObserver
        public boolean deliverSelfNotifications() {
            return super.deliverSelfNotifications();
        }

        @Override // android.database.ContentObserver
        public void onChange(boolean selfChange) {
            super.onChange(selfChange);
            AudioManager audioManager = (AudioManager) this.context.getSystemService("audio");
            if (audioManager != null) {
                int scale = audioManager.getStreamMaxVolume(3) / audioManager.getStreamMaxVolume(0);
                int currentVolume = audioManager.getStreamVolume(0);
                if (RingUtils.mbytLast == currentVolume && currentVolume == 1 && RingUtils.mbytLast < audioManager.getStreamMaxVolume(0)) {
                    currentVolume = 0;
                }
                int curentMusic = currentVolume * scale;
                if (curentMusic != audioManager.getStreamVolume(3)) {
                    audioManager.setStreamVolume(3, curentMusic, 4);
                    KLog.d("currVolume:" + curentMusic);
                }
                byte unused = RingUtils.mbytLast = (byte) audioManager.getStreamVolume(0);
            }
        }
    }
}
