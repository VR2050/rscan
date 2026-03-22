package p005b.p310s.p311a;

import android.annotation.TargetApi;
import android.app.Activity;
import android.content.Context;
import android.content.SharedPreferences;
import android.content.res.AssetFileDescriptor;
import android.media.AudioManager;
import android.media.MediaPlayer;
import android.preference.PreferenceManager;
import com.king.zxing.R$raw;
import java.io.Closeable;
import java.io.IOException;

/* renamed from: b.s.a.g */
/* loaded from: classes2.dex */
public final class C2737g implements MediaPlayer.OnErrorListener, Closeable {

    /* renamed from: c */
    public static final String f7445c = C2737g.class.getSimpleName();

    /* renamed from: e */
    public final Activity f7446e;

    /* renamed from: f */
    public MediaPlayer f7447f = null;

    /* renamed from: g */
    public boolean f7448g;

    /* renamed from: h */
    public boolean f7449h;

    public C2737g(Activity activity) {
        this.f7446e = activity;
        m3243d();
    }

    @TargetApi(19)
    /* renamed from: b */
    public final MediaPlayer m3242b(Context context) {
        MediaPlayer mediaPlayer = new MediaPlayer();
        try {
            AssetFileDescriptor openRawResourceFd = context.getResources().openRawResourceFd(R$raw.zxl_beep);
            try {
                mediaPlayer.setDataSource(openRawResourceFd.getFileDescriptor(), openRawResourceFd.getStartOffset(), openRawResourceFd.getLength());
                mediaPlayer.setOnErrorListener(this);
                mediaPlayer.setAudioStreamType(3);
                mediaPlayer.setLooping(false);
                mediaPlayer.setVolume(0.1f, 0.1f);
                mediaPlayer.prepare();
                openRawResourceFd.close();
                return mediaPlayer;
            } finally {
            }
        } catch (IOException unused) {
            mediaPlayer.release();
            return null;
        }
    }

    @Override // java.io.Closeable, java.lang.AutoCloseable
    public synchronized void close() {
        MediaPlayer mediaPlayer = this.f7447f;
        if (mediaPlayer != null) {
            mediaPlayer.release();
            this.f7447f = null;
        }
    }

    /* renamed from: d */
    public synchronized void m3243d() {
        SharedPreferences defaultSharedPreferences = PreferenceManager.getDefaultSharedPreferences(this.f7446e);
        Activity activity = this.f7446e;
        if (defaultSharedPreferences.getBoolean("preferences_play_beep", false)) {
            ((AudioManager) activity.getApplicationContext().getSystemService("audio")).getRingerMode();
        }
        if (this.f7448g && this.f7447f == null) {
            this.f7446e.setVolumeControlStream(3);
            this.f7447f = m3242b(this.f7446e);
        }
    }

    @Override // android.media.MediaPlayer.OnErrorListener
    public synchronized boolean onError(MediaPlayer mediaPlayer, int i2, int i3) {
        if (i2 == 100) {
            this.f7446e.finish();
        } else {
            close();
            m3243d();
        }
        return true;
    }
}
