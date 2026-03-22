package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.ProgressBar;
import android.widget.RelativeLayout;
import android.widget.SeekBar;
import android.widget.TextView;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.constraintlayout.widget.ConstraintLayout;
import androidx.viewbinding.ViewBinding;
import com.github.mmin18.widget.RealtimeBlurView;
import com.jbzd.media.movecartoons.view.image.CircleImageView;
import com.jbzd.media.movecartoons.view.text.ImageTextView;
import com.qnmd.adnnm.da0yzo.R;
import com.qunidayede.supportlibrary.widget.MarqueeTextView;

/* loaded from: classes2.dex */
public final class ActNovelPlayingBinding implements ViewBinding {

    @NonNull
    public final FrameLayout albumLayout;

    @NonNull
    public final FrameLayout albumLayoutBig;

    @NonNull
    public final RealtimeBlurView blurViewPlaying;

    @NonNull
    public final ImageView btnPlayPause;

    @NonNull
    public final RelativeLayout btnTitleBack;

    @NonNull
    public final RelativeLayout btnTitleRight;

    @NonNull
    public final View circleView;

    @NonNull
    public final View firstView;

    @NonNull
    public final ImageTextView itvVoicenovelBackFifiteen;

    @NonNull
    public final ImageTextView itvVoicenovelChapterList;

    @NonNull
    public final ImageTextView itvVoicenovelFastFifiteen;

    @NonNull
    public final ImageTextView itvVoicenovelReadSpeed;

    @NonNull
    public final ImageTextView itvVoicenovelTimer;

    @NonNull
    public final ImageView ivTitleLeftIcon;

    @NonNull
    public final ImageView ivVoicenovelPlayLast;

    @NonNull
    public final ImageView ivVoicenovelPlayNext;

    @NonNull
    public final ProgressBar loadingProgressBar;

    @NonNull
    public final CircleImageView musicAlbum;

    @NonNull
    public final ImageView musicCover;

    @NonNull
    public final ImageView musicPointer;

    @NonNull
    public final ImageView musicTurntable;

    @NonNull
    public final View overlayView;

    @NonNull
    public final ConstraintLayout playBar;

    @NonNull
    public final SeekBar progressBar;

    @NonNull
    private final FrameLayout rootView;

    @NonNull
    public final View secView;

    @NonNull
    public final RelativeLayout titleLayout;

    @NonNull
    public final MarqueeTextView tvNovelchapterName;

    @NonNull
    public final TextView tvTitleRight;

    @NonNull
    public final TextView tvVoicenovelName;

    @NonNull
    public final TextView tvVoicenovelTimeCur;

    @NonNull
    public final TextView tvVoicenovelTimeEnd;

    private ActNovelPlayingBinding(@NonNull FrameLayout frameLayout, @NonNull FrameLayout frameLayout2, @NonNull FrameLayout frameLayout3, @NonNull RealtimeBlurView realtimeBlurView, @NonNull ImageView imageView, @NonNull RelativeLayout relativeLayout, @NonNull RelativeLayout relativeLayout2, @NonNull View view, @NonNull View view2, @NonNull ImageTextView imageTextView, @NonNull ImageTextView imageTextView2, @NonNull ImageTextView imageTextView3, @NonNull ImageTextView imageTextView4, @NonNull ImageTextView imageTextView5, @NonNull ImageView imageView2, @NonNull ImageView imageView3, @NonNull ImageView imageView4, @NonNull ProgressBar progressBar, @NonNull CircleImageView circleImageView, @NonNull ImageView imageView5, @NonNull ImageView imageView6, @NonNull ImageView imageView7, @NonNull View view3, @NonNull ConstraintLayout constraintLayout, @NonNull SeekBar seekBar, @NonNull View view4, @NonNull RelativeLayout relativeLayout3, @NonNull MarqueeTextView marqueeTextView, @NonNull TextView textView, @NonNull TextView textView2, @NonNull TextView textView3, @NonNull TextView textView4) {
        this.rootView = frameLayout;
        this.albumLayout = frameLayout2;
        this.albumLayoutBig = frameLayout3;
        this.blurViewPlaying = realtimeBlurView;
        this.btnPlayPause = imageView;
        this.btnTitleBack = relativeLayout;
        this.btnTitleRight = relativeLayout2;
        this.circleView = view;
        this.firstView = view2;
        this.itvVoicenovelBackFifiteen = imageTextView;
        this.itvVoicenovelChapterList = imageTextView2;
        this.itvVoicenovelFastFifiteen = imageTextView3;
        this.itvVoicenovelReadSpeed = imageTextView4;
        this.itvVoicenovelTimer = imageTextView5;
        this.ivTitleLeftIcon = imageView2;
        this.ivVoicenovelPlayLast = imageView3;
        this.ivVoicenovelPlayNext = imageView4;
        this.loadingProgressBar = progressBar;
        this.musicAlbum = circleImageView;
        this.musicCover = imageView5;
        this.musicPointer = imageView6;
        this.musicTurntable = imageView7;
        this.overlayView = view3;
        this.playBar = constraintLayout;
        this.progressBar = seekBar;
        this.secView = view4;
        this.titleLayout = relativeLayout3;
        this.tvNovelchapterName = marqueeTextView;
        this.tvTitleRight = textView;
        this.tvVoicenovelName = textView2;
        this.tvVoicenovelTimeCur = textView3;
        this.tvVoicenovelTimeEnd = textView4;
    }

    @NonNull
    public static ActNovelPlayingBinding bind(@NonNull View view) {
        int i2 = R.id.album_layout;
        FrameLayout frameLayout = (FrameLayout) view.findViewById(R.id.album_layout);
        if (frameLayout != null) {
            i2 = R.id.album_layout_big;
            FrameLayout frameLayout2 = (FrameLayout) view.findViewById(R.id.album_layout_big);
            if (frameLayout2 != null) {
                i2 = R.id.blur_view_playing;
                RealtimeBlurView realtimeBlurView = (RealtimeBlurView) view.findViewById(R.id.blur_view_playing);
                if (realtimeBlurView != null) {
                    i2 = R.id.btn_play_pause;
                    ImageView imageView = (ImageView) view.findViewById(R.id.btn_play_pause);
                    if (imageView != null) {
                        i2 = R.id.btn_titleBack;
                        RelativeLayout relativeLayout = (RelativeLayout) view.findViewById(R.id.btn_titleBack);
                        if (relativeLayout != null) {
                            i2 = R.id.btn_titleRight;
                            RelativeLayout relativeLayout2 = (RelativeLayout) view.findViewById(R.id.btn_titleRight);
                            if (relativeLayout2 != null) {
                                i2 = R.id.circle_view;
                                View findViewById = view.findViewById(R.id.circle_view);
                                if (findViewById != null) {
                                    i2 = R.id.firstView;
                                    View findViewById2 = view.findViewById(R.id.firstView);
                                    if (findViewById2 != null) {
                                        i2 = R.id.itv_voicenovel_back_fifiteen;
                                        ImageTextView imageTextView = (ImageTextView) view.findViewById(R.id.itv_voicenovel_back_fifiteen);
                                        if (imageTextView != null) {
                                            i2 = R.id.itv_voicenovel_chapter_list;
                                            ImageTextView imageTextView2 = (ImageTextView) view.findViewById(R.id.itv_voicenovel_chapter_list);
                                            if (imageTextView2 != null) {
                                                i2 = R.id.itv_voicenovel_fast_fifiteen;
                                                ImageTextView imageTextView3 = (ImageTextView) view.findViewById(R.id.itv_voicenovel_fast_fifiteen);
                                                if (imageTextView3 != null) {
                                                    i2 = R.id.itv_voicenovel_read_speed;
                                                    ImageTextView imageTextView4 = (ImageTextView) view.findViewById(R.id.itv_voicenovel_read_speed);
                                                    if (imageTextView4 != null) {
                                                        i2 = R.id.itv_voicenovel_timer;
                                                        ImageTextView imageTextView5 = (ImageTextView) view.findViewById(R.id.itv_voicenovel_timer);
                                                        if (imageTextView5 != null) {
                                                            i2 = R.id.iv_titleLeftIcon;
                                                            ImageView imageView2 = (ImageView) view.findViewById(R.id.iv_titleLeftIcon);
                                                            if (imageView2 != null) {
                                                                i2 = R.id.iv_voicenovel_play_last;
                                                                ImageView imageView3 = (ImageView) view.findViewById(R.id.iv_voicenovel_play_last);
                                                                if (imageView3 != null) {
                                                                    i2 = R.id.iv_voicenovel_play_next;
                                                                    ImageView imageView4 = (ImageView) view.findViewById(R.id.iv_voicenovel_play_next);
                                                                    if (imageView4 != null) {
                                                                        i2 = R.id.loading_progress_bar;
                                                                        ProgressBar progressBar = (ProgressBar) view.findViewById(R.id.loading_progress_bar);
                                                                        if (progressBar != null) {
                                                                            i2 = R.id.music_album;
                                                                            CircleImageView circleImageView = (CircleImageView) view.findViewById(R.id.music_album);
                                                                            if (circleImageView != null) {
                                                                                i2 = R.id.music_cover;
                                                                                ImageView imageView5 = (ImageView) view.findViewById(R.id.music_cover);
                                                                                if (imageView5 != null) {
                                                                                    i2 = R.id.music_pointer;
                                                                                    ImageView imageView6 = (ImageView) view.findViewById(R.id.music_pointer);
                                                                                    if (imageView6 != null) {
                                                                                        i2 = R.id.music_turntable;
                                                                                        ImageView imageView7 = (ImageView) view.findViewById(R.id.music_turntable);
                                                                                        if (imageView7 != null) {
                                                                                            i2 = R.id.overlay_view;
                                                                                            View findViewById3 = view.findViewById(R.id.overlay_view);
                                                                                            if (findViewById3 != null) {
                                                                                                i2 = R.id.play_bar;
                                                                                                ConstraintLayout constraintLayout = (ConstraintLayout) view.findViewById(R.id.play_bar);
                                                                                                if (constraintLayout != null) {
                                                                                                    i2 = R.id.progress_bar;
                                                                                                    SeekBar seekBar = (SeekBar) view.findViewById(R.id.progress_bar);
                                                                                                    if (seekBar != null) {
                                                                                                        i2 = R.id.secView;
                                                                                                        View findViewById4 = view.findViewById(R.id.secView);
                                                                                                        if (findViewById4 != null) {
                                                                                                            i2 = R.id.title_layout;
                                                                                                            RelativeLayout relativeLayout3 = (RelativeLayout) view.findViewById(R.id.title_layout);
                                                                                                            if (relativeLayout3 != null) {
                                                                                                                i2 = R.id.tv_novelchapter_name;
                                                                                                                MarqueeTextView marqueeTextView = (MarqueeTextView) view.findViewById(R.id.tv_novelchapter_name);
                                                                                                                if (marqueeTextView != null) {
                                                                                                                    i2 = R.id.tv_titleRight;
                                                                                                                    TextView textView = (TextView) view.findViewById(R.id.tv_titleRight);
                                                                                                                    if (textView != null) {
                                                                                                                        i2 = R.id.tv_voicenovel_name;
                                                                                                                        TextView textView2 = (TextView) view.findViewById(R.id.tv_voicenovel_name);
                                                                                                                        if (textView2 != null) {
                                                                                                                            i2 = R.id.tv_voicenovel_time_cur;
                                                                                                                            TextView textView3 = (TextView) view.findViewById(R.id.tv_voicenovel_time_cur);
                                                                                                                            if (textView3 != null) {
                                                                                                                                i2 = R.id.tv_voicenovel_time_end;
                                                                                                                                TextView textView4 = (TextView) view.findViewById(R.id.tv_voicenovel_time_end);
                                                                                                                                if (textView4 != null) {
                                                                                                                                    return new ActNovelPlayingBinding((FrameLayout) view, frameLayout, frameLayout2, realtimeBlurView, imageView, relativeLayout, relativeLayout2, findViewById, findViewById2, imageTextView, imageTextView2, imageTextView3, imageTextView4, imageTextView5, imageView2, imageView3, imageView4, progressBar, circleImageView, imageView5, imageView6, imageView7, findViewById3, constraintLayout, seekBar, findViewById4, relativeLayout3, marqueeTextView, textView, textView2, textView3, textView4);
                                                                                                                                }
                                                                                                                            }
                                                                                                                        }
                                                                                                                    }
                                                                                                                }
                                                                                                            }
                                                                                                        }
                                                                                                    }
                                                                                                }
                                                                                            }
                                                                                        }
                                                                                    }
                                                                                }
                                                                            }
                                                                        }
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i2)));
    }

    @NonNull
    public static ActNovelPlayingBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static ActNovelPlayingBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.act_novel_playing, viewGroup, false);
        if (z) {
            viewGroup.addView(inflate);
        }
        return bind(inflate);
    }

    @Override // androidx.viewbinding.ViewBinding
    @NonNull
    public FrameLayout getRoot() {
        return this.rootView;
    }
}
