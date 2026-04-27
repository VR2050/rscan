package im.uwrkaxlmjj.ui.hui.friendscircle_v1.player.player;

import android.app.Activity;
import android.app.Dialog;
import android.content.Context;
import android.graphics.Canvas;
import android.graphics.Color;
import android.view.Display;
import android.view.MotionEvent;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.RelativeLayout;
import android.widget.TextView;
import com.google.android.exoplayer2.C;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.ui.components.LayoutHelper;
import im.uwrkaxlmjj.ui.components.SeekBar;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.player.view.AbsMultiVideoPlayerView;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class FullScreenExoMultiPlayer extends Dialog {
    private static final int PROGRESS_UPDATE_INITIAL_INTERVAL = 100;
    private static final int PROGRESS_UPDATE_INTERNAL = 300;
    private boolean blnMute;
    Context context;
    FrameLayout flSeekbar;
    private ImageView iv_mute;
    private ImageView iv_play;
    private LinearLayout ll_state_bar;
    private LinearLayout ll_title_bar;
    private int mDuration;
    private final ScheduledExecutorService mExecutorService;
    private ScheduledFuture<?> mScheduleFuture;
    private final Runnable mUpdateProgressTask;
    dismissListener mdismissListener;
    RelativeLayout root_view;
    private TextView tv_current_time;
    private TextView tv_title;
    private TextView tv_total_time;
    FrameLayout videoPlayerControlFrameLayout;
    private SeekBar videoPlayerSeekbar;

    public interface dismissListener {
        void doDismissCallback();
    }

    public FullScreenExoMultiPlayer(final Context context, AbsMultiVideoPlayerView player, float Ratio, final boolean blnShowExtension, String strTitle, dismissListener Listener) {
        super(context, R.plurals.DialogTheme);
        this.blnMute = false;
        this.mExecutorService = Executors.newSingleThreadScheduledExecutor();
        this.mUpdateProgressTask = new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.player.player.-$$Lambda$FullScreenExoMultiPlayer$akJdDay2Hroiza7rCSA6DshnOEE
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$new$5$FullScreenExoMultiPlayer();
            }
        };
        this.mdismissListener = Listener;
        this.context = context;
        View view = getLayoutInflater().inflate(R.layout.full_screen_exoplayer, (ViewGroup) null);
        this.root_view = (RelativeLayout) view.findViewById(R.attr.root_view);
        this.flSeekbar = (FrameLayout) view.findViewById(R.attr.fl_seekbar);
        this.tv_total_time = (TextView) view.findViewById(R.attr.tv_total_time);
        this.tv_current_time = (TextView) view.findViewById(R.attr.tv_current_time);
        this.iv_play = (ImageView) view.findViewById(R.attr.iv_play);
        this.iv_mute = (ImageView) view.findViewById(R.attr.iv_mute);
        this.ll_title_bar = (LinearLayout) view.findViewById(R.attr.ll_title_bar);
        this.ll_state_bar = (LinearLayout) view.findViewById(R.attr.ll_state_bar);
        this.tv_title = (TextView) view.findViewById(R.attr.tv_title);
        setContentView(view);
        getWindow().setLayout(-1, -1);
        Display display = ((Activity) context).getWindowManager().getDefaultDisplay();
        int width = display.getWidth();
        display.getHeight();
        int mVideoHeight = (int) (width / Ratio);
        FrameLayout.LayoutParams lp = new FrameLayout.LayoutParams(-1, mVideoHeight == 0 ? -2 : mVideoHeight, 17);
        this.root_view.addView(player, lp);
        if (blnShowExtension) {
            this.ll_state_bar.setVisibility(0);
            this.ll_title_bar.setVisibility(0);
            this.mDuration = VideoPlayerManager.getInstance().getDuration();
            this.tv_title.setText(strTitle);
            createSeekBar(player);
            startVideoProgressUpdate();
            setCanceledOnTouchOutside(false);
            view.findViewById(R.attr.ll_return).setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.player.player.-$$Lambda$FullScreenExoMultiPlayer$hn5UV_vVqcBgw7leaiOVi-TY9R8
                @Override // android.view.View.OnClickListener
                public final void onClick(View view2) {
                    this.f$0.lambda$new$0$FullScreenExoMultiPlayer(view2);
                }
            });
            this.iv_play.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.player.player.-$$Lambda$FullScreenExoMultiPlayer$mJS1YZmvQCZVFZha6MDPBJ66A0s
                @Override // android.view.View.OnClickListener
                public final void onClick(View view2) {
                    this.f$0.lambda$new$1$FullScreenExoMultiPlayer(view2);
                }
            });
            this.iv_mute.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.player.player.-$$Lambda$FullScreenExoMultiPlayer$i8VoQkQxAoD_EBWpjeJ93k8PMpw
                @Override // android.view.View.OnClickListener
                public final void onClick(View view2) {
                    this.f$0.lambda$new$2$FullScreenExoMultiPlayer(view2);
                }
            });
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.player.player.-$$Lambda$FullScreenExoMultiPlayer$PJLP9agyNoZci-0wrA4euJwiYxA
                @Override // java.lang.Runnable
                public final void run() {
                    ((Activity) context).setRequestedOrientation(1);
                }
            }, 1000L);
        }
        VideoPlayerManager.getInstance().play();
        this.root_view.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.player.player.FullScreenExoMultiPlayer.1
            @Override // android.view.View.OnClickListener
            public void onClick(View view2) {
                if (!blnShowExtension) {
                    if (FullScreenExoMultiPlayer.this.root_view.getChildAt(0) != null) {
                        FullScreenExoMultiPlayer.this.mdismissListener.doDismissCallback();
                    }
                    FullScreenExoMultiPlayer.this.root_view.removeAllViews();
                    FullScreenExoMultiPlayer.this.dismiss();
                }
            }
        });
    }

    public /* synthetic */ void lambda$new$0$FullScreenExoMultiPlayer(View v) {
        if (this.root_view.getChildAt(0) != null) {
            this.mdismissListener.doDismissCallback();
        }
        this.root_view.removeAllViews();
        dismiss();
    }

    public /* synthetic */ void lambda$new$1$FullScreenExoMultiPlayer(View v) {
        if (VideoPlayerManager.getInstance().getState() == 2) {
            VideoPlayerManager.getInstance().pause();
            this.iv_play.setImageResource(R.drawable.ic_play);
        } else if (VideoPlayerManager.getInstance().getState() == 4) {
            VideoPlayerManager.getInstance().play();
            this.iv_play.setImageResource(R.drawable.ic_pause);
        }
    }

    public /* synthetic */ void lambda$new$2$FullScreenExoMultiPlayer(View v) {
        if (this.blnMute) {
            VideoPlayerManager.getInstance().setVolume(4);
            this.iv_mute.setImageResource(R.id.ic_game_share_unmute);
            this.blnMute = false;
        } else {
            VideoPlayerManager.getInstance().setVolume(0);
            this.iv_mute.setImageResource(R.id.ic_game_share_mute);
            this.blnMute = true;
        }
    }

    public View getView() {
        View view = this.root_view.getChildAt(0);
        this.root_view.removeAllViews();
        dismiss();
        return view;
    }

    private void createSeekBar(final AbsMultiVideoPlayerView player) {
        SeekBar seekBar = new SeekBar(getContext());
        this.videoPlayerSeekbar = seekBar;
        seekBar.setLineHeight(AndroidUtilities.dp(4.0f));
        this.videoPlayerSeekbar.setColors(Color.parseColor("#4D4D4D"), Color.parseColor("#4D4D4D"), Color.parseColor("#FE6022"), Color.parseColor("#FE6022"), Color.parseColor("#4D4D4D"));
        this.videoPlayerSeekbar.setDelegate(new SeekBar.SeekBarDelegate() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.player.player.FullScreenExoMultiPlayer.2
            @Override // im.uwrkaxlmjj.ui.components.SeekBar.SeekBarDelegate
            public void onSeekBarDrag(float progress) {
                if (VideoPlayerManager.getInstance() != null) {
                    long duration = player.getmDuration();
                    VideoPlayerManager.getInstance().seekTo((int) (duration * progress));
                }
            }

            @Override // im.uwrkaxlmjj.ui.components.SeekBar.SeekBarDelegate
            public void onSeekBarContinuousDrag(float progress) {
            }
        });
        FrameLayout frameLayout = new FrameLayout(getContext()) { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.player.player.FullScreenExoMultiPlayer.3
            @Override // android.view.View
            public boolean onTouchEvent(MotionEvent event) {
                if (!FullScreenExoMultiPlayer.this.videoPlayerSeekbar.onTouchNew(event.getAction(), event.getX(), event.getY())) {
                    return true;
                }
                getParent().requestDisallowInterceptTouchEvent(true);
                invalidate();
                return true;
            }

            @Override // android.widget.FrameLayout, android.view.View
            protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
                long duration;
                super.onMeasure(widthMeasureSpec, heightMeasureSpec);
                if (VideoPlayerManager.getInstance() != null) {
                    duration = player.getmDuration();
                    if (duration == C.TIME_UNSET) {
                        duration = 0;
                    }
                } else {
                    duration = 0;
                }
                long j = duration / 1000;
                FullScreenExoMultiPlayer.this.videoPlayerSeekbar.setSize(getMeasuredWidth(), getMeasuredHeight());
            }

            @Override // android.widget.FrameLayout, android.view.ViewGroup, android.view.View
            protected void onLayout(boolean changed, int left, int top, int right, int bottom) {
                super.onLayout(changed, left, top, right, bottom);
                FullScreenExoMultiPlayer.this.videoPlayerSeekbar.setProgress(0.0f);
            }

            @Override // android.view.View
            protected void onDraw(Canvas canvas) {
                canvas.save();
                canvas.translate(0.0f, 0.0f);
                FullScreenExoMultiPlayer.this.videoPlayerSeekbar.draw(canvas);
                canvas.restore();
            }
        };
        this.videoPlayerControlFrameLayout = frameLayout;
        this.flSeekbar.addView(frameLayout, LayoutHelper.createFrame(-1, -1, 51));
        this.tv_total_time.setText(String.format("%02d:%02d", Integer.valueOf((this.mDuration / 1000) / 60), Integer.valueOf((this.mDuration / 1000) % 60)));
    }

    private void startVideoProgressUpdate() {
        stopVideoProgressUpdate();
        if (!this.mExecutorService.isShutdown()) {
            this.mScheduleFuture = this.mExecutorService.scheduleAtFixedRate(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.player.player.-$$Lambda$FullScreenExoMultiPlayer$E7c6Q32EEla4hMOVwZBf0PCeYR0
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$startVideoProgressUpdate$4$FullScreenExoMultiPlayer();
                }
            }, 100L, 300L, TimeUnit.MILLISECONDS);
        }
    }

    public /* synthetic */ void lambda$startVideoProgressUpdate$4$FullScreenExoMultiPlayer() {
        AndroidUtilities.runOnUIThread(this.mUpdateProgressTask);
    }

    private void stopVideoProgressUpdate() {
        ScheduledFuture<?> scheduledFuture = this.mScheduleFuture;
        if (scheduledFuture != null) {
            scheduledFuture.cancel(false);
        }
    }

    public /* synthetic */ void lambda$new$5$FullScreenExoMultiPlayer() {
        int position = VideoPlayerManager.getInstance().getCurrentPosition();
        updateProgress(position);
    }

    private void updateProgress(int position) {
        float progress = position / this.mDuration;
        this.videoPlayerSeekbar.setProgress(progress);
        this.tv_current_time.setText(String.format("%02d:%02d", Integer.valueOf((position / 1000) / 60), Integer.valueOf((position / 1000) % 60)));
        this.videoPlayerControlFrameLayout.invalidate();
        updatePlayState();
    }

    private void updatePlayState() {
        if (VideoPlayerManager.getInstance().getState() == 2) {
            if (!String.valueOf(this.iv_play.getTag()).equals("ic_play")) {
                this.iv_play.setImageResource(R.drawable.ic_pause);
                this.iv_play.setTag("ic_play");
                return;
            }
            return;
        }
        if (VideoPlayerManager.getInstance().getState() == 4 && !String.valueOf(this.iv_play.getTag()).equals("ic_pause")) {
            this.iv_play.setImageResource(R.drawable.ic_play);
            this.iv_play.setTag("ic_pause");
        }
    }

    @Override // android.app.Dialog, android.content.DialogInterface
    public void dismiss() {
        if (this.root_view.getChildAt(0) != null) {
            this.mdismissListener.doDismissCallback();
        }
        this.root_view.removeAllViews();
        super.dismiss();
    }
}
