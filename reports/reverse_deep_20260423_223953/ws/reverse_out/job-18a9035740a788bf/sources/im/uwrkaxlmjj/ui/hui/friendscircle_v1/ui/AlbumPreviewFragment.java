package im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui;

import android.app.Activity;
import android.content.Context;
import android.os.Bundle;
import android.os.Handler;
import android.text.TextUtils;
import android.view.LayoutInflater;
import android.view.TextureView;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import android.widget.ProgressBar;
import com.bjz.comm.net.bean.UrlInfoBean;
import com.preview.photoview.PhotoView;
import im.uwrkaxlmjj.ui.fragments.BaseFmts;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.glide.GlideUtils;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.listener.OnPreviewClickListener;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.listener.OnPreviewLongClickListener;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.player.message.BackPressedMessage;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.player.message.DurationMessage;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.player.message.Message;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.player.message.UIStateMessage;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.player.player.VideoPlayerManager;
import im.uwrkaxlmjj.ui.hviews.dialogs.Util;
import java.util.Observable;
import java.util.Observer;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class AlbumPreviewFragment extends BaseFmts implements Observer {
    private static final int TYPE_IMG = 0;
    private static final int TYPE_VIDEO = 1;
    private Context mContext;
    private Handler mHandler;
    private String mImgUrl;
    private ProgressBar mLoading;
    private OnPreviewClickListener mOnPreviewClickListener;
    private OnPreviewLongClickListener mOnPreviewLongClickListener;
    private PhotoView mPhotoView;
    private FrameLayout mRoot;
    private ScheduledFuture<?> mSchedule;
    private ScheduledExecutorService mService;
    private FrameLayout mVideoContainer;
    private String mVideoUrl;
    private TextureView textureView;
    private UrlInfoBean urlInfoBean;
    private long mDelayShowProgressTime = 100;
    private int urlType = 0;
    private int hashCode = 0;
    private int currentIndex = -1;
    private boolean isResume = false;

    @Override // im.uwrkaxlmjj.ui.fragments.BaseFmts, androidx.fragment.app.Fragment
    public void onAttach(Context context) {
        super.onAttach(context);
        this.mContext = context;
    }

    @Override // im.uwrkaxlmjj.ui.fragments.BaseFmts, androidx.fragment.app.Fragment
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        if (savedInstanceState == null) {
            initData();
        }
    }

    private void initData() {
        this.mService = Executors.newScheduledThreadPool(1);
        this.mHandler = new Handler();
    }

    @Override // im.uwrkaxlmjj.ui.fragments.BaseFmts, androidx.fragment.app.Fragment
    public View onCreateView(LayoutInflater inflater, ViewGroup container, Bundle savedInstanceState) {
        if (savedInstanceState == null) {
            this.fragmentView = inflater.inflate(R.layout.fragment_album_preview, (ViewGroup) null);
            FrameLayout frameLayout = (FrameLayout) this.fragmentView.findViewById(R.attr.root);
            this.mRoot = frameLayout;
            frameLayout.setFocusableInTouchMode(true);
            this.mRoot.requestFocus();
            this.mVideoContainer = (FrameLayout) this.fragmentView.findViewById(R.attr.tv_video_container);
            this.mPhotoView = (PhotoView) this.fragmentView.findViewById(R.attr.photoView);
            this.mLoading = (ProgressBar) this.fragmentView.findViewById(R.attr.loading);
            initListener();
            onLoadData();
        }
        return this.fragmentView;
    }

    @Override // im.uwrkaxlmjj.ui.fragments.BaseFmts, androidx.fragment.app.Fragment
    public void onDestroyView() {
        super.onDestroyView();
        VideoPlayerManager.getInstance().removeObserver(this);
        if (this.urlType == 1 && VideoPlayerManager.getInstance().isViewPlaying(this.hashCode)) {
            VideoPlayerManager.getInstance().stop();
        }
        this.hashCode = 0;
        this.textureView = null;
    }

    @Override // im.uwrkaxlmjj.ui.fragments.BaseFmts
    protected void lazyLoadData() {
        super.lazyLoadData();
        onVisible();
    }

    @Override // androidx.fragment.app.Fragment
    public void onResume() {
        super.onResume();
        if (!isFirstTimeInThisPage() && !this.isResume && isFragmentVisible()) {
            this.isResume = true;
            onVisible();
        }
    }

    @Override // androidx.fragment.app.Fragment
    public void onPause() {
        super.onPause();
        if (!isFirstTimeInThisPage() && this.isResume && isFragmentVisible()) {
            this.isResume = false;
            onInvisible();
        }
    }

    @Override // im.uwrkaxlmjj.ui.fragments.BaseFmts
    protected void onVisible() {
        super.onVisible();
        if (this.urlType == 1) {
            if (this.textureView == null || this.hashCode == 0) {
                TextureView textureViewCreateTextureView = createTextureView();
                this.textureView = textureViewCreateTextureView;
                this.hashCode = textureViewCreateTextureView.hashCode();
                ViewGroup.LayoutParams layoutParams = this.textureView.getLayoutParams();
                int mVideoHeight = layoutParams.height;
                UrlInfoBean urlInfoBean = this.urlInfoBean;
                if (urlInfoBean != null) {
                    float ratio = urlInfoBean.getVideoWidth() / this.urlInfoBean.getVideoHeight();
                    int screenWidth = Util.getScreenWidth(getParentActivity());
                    if (ratio > 1.0f) {
                        mVideoHeight = (int) (screenWidth / ratio);
                    }
                }
                layoutParams.height = mVideoHeight;
                FrameLayout frameLayout = this.mVideoContainer;
                if (frameLayout != null) {
                    frameLayout.addView(this.textureView, layoutParams);
                }
            }
            if (!VideoPlayerManager.getInstance().isViewPlaying(this.hashCode)) {
                VideoPlayerManager.getInstance().stopWithKeepView();
                if (!TextUtils.isEmpty(this.mVideoUrl)) {
                    VideoPlayerManager.getInstance().start(this.mVideoUrl, this.hashCode);
                    VideoPlayerManager.getInstance().setTextureView(this.textureView);
                }
            } else {
                VideoPlayerManager.getInstance().resume();
            }
            PhotoView photoView = this.mPhotoView;
            if (photoView != null) {
                photoView.setVisibility(8);
                return;
            }
            return;
        }
        VideoPlayerManager.getInstance().stopWithKeepView();
    }

    @Override // im.uwrkaxlmjj.ui.fragments.BaseFmts
    protected void onInvisible() {
        super.onInvisible();
        PhotoView photoView = this.mPhotoView;
        if (photoView != null) {
            photoView.setScale(1.0f);
        }
        getParentActivity().getWindow().clearFlags(128);
        if (this.urlType == 1) {
            PhotoView photoView2 = this.mPhotoView;
            if (photoView2 != null) {
                photoView2.setVisibility(0);
            }
            if (VideoPlayerManager.getInstance().isViewPlaying(this.hashCode)) {
                VideoPlayerManager.getInstance().stopWithKeepView();
            }
        }
    }

    private void initListener() {
        this.mVideoContainer.setOnLongClickListener(new View.OnLongClickListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.AlbumPreviewFragment.1
            @Override // android.view.View.OnLongClickListener
            public boolean onLongClick(View v) {
                if (AlbumPreviewFragment.this.mOnPreviewLongClickListener != null) {
                    AlbumPreviewFragment.this.mOnPreviewLongClickListener.onLongClick(AlbumPreviewFragment.this.urlInfoBean, AlbumPreviewFragment.this.currentIndex);
                    return false;
                }
                return false;
            }
        });
        this.mPhotoView.setOnLongClickListener(new View.OnLongClickListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.AlbumPreviewFragment.2
            @Override // android.view.View.OnLongClickListener
            public boolean onLongClick(View v) {
                if (AlbumPreviewFragment.this.mOnPreviewLongClickListener != null) {
                    AlbumPreviewFragment.this.mOnPreviewLongClickListener.onLongClick(AlbumPreviewFragment.this.urlInfoBean, AlbumPreviewFragment.this.currentIndex);
                    return true;
                }
                return true;
            }
        });
        this.mVideoContainer.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.AlbumPreviewFragment.3
            @Override // android.view.View.OnClickListener
            public void onClick(View v) {
                if (AlbumPreviewFragment.this.mOnPreviewClickListener != null) {
                    AlbumPreviewFragment.this.mOnPreviewClickListener.onClick();
                }
            }
        });
        this.mPhotoView.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.AlbumPreviewFragment.4
            @Override // android.view.View.OnClickListener
            public void onClick(View v) {
                if (AlbumPreviewFragment.this.mOnPreviewClickListener != null) {
                    AlbumPreviewFragment.this.mOnPreviewClickListener.onClick();
                }
            }
        });
    }

    private void onLoadData() {
        if (!TextUtils.isEmpty(this.mImgUrl)) {
            if (this.urlType == 1) {
                this.mVideoContainer.setVisibility(0);
                VideoPlayerManager.getInstance().addObserver(this);
            } else {
                this.mVideoContainer.setVisibility(8);
            }
            GlideUtils.getInstance().loadNOCentercrop(this.mImgUrl, this.mContext, this.mPhotoView, 0);
            if (this.urlType == 0) {
                checkLoadResult();
            }
        }
    }

    private void checkLoadResult() {
        long j = this.mDelayShowProgressTime;
        if (j < 0) {
            this.mLoading.setVisibility(8);
            return;
        }
        this.mLoading.setVisibility(j == 0 ? 0 : 8);
        ScheduledExecutorService scheduledExecutorService = this.mService;
        Runnable runnable = new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.AlbumPreviewFragment.5
            @Override // java.lang.Runnable
            public void run() {
                if (AlbumPreviewFragment.this.mPhotoView.getDrawable() != null) {
                    AlbumPreviewFragment.this.mHandler.post(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.AlbumPreviewFragment.5.1
                        @Override // java.lang.Runnable
                        public void run() {
                            AlbumPreviewFragment.this.mLoading.setVisibility(8);
                        }
                    });
                    AlbumPreviewFragment.this.mSchedule.cancel(true);
                } else if (AlbumPreviewFragment.this.mLoading.getVisibility() == 8) {
                    AlbumPreviewFragment.this.mHandler.post(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.AlbumPreviewFragment.5.2
                        @Override // java.lang.Runnable
                        public void run() {
                            AlbumPreviewFragment.this.mLoading.setVisibility(0);
                        }
                    });
                }
            }
        };
        long j2 = this.mDelayShowProgressTime;
        if (j2 == 0) {
            j2 = 100;
        }
        this.mSchedule = scheduledExecutorService.scheduleWithFixedDelay(runnable, j2, 100L, TimeUnit.MILLISECONDS);
    }

    public void setData(UrlInfoBean urlInfoBean, int currentIndex) {
        if (urlInfoBean != null) {
            this.urlInfoBean = urlInfoBean;
            this.currentIndex = currentIndex;
            this.mImgUrl = urlInfoBean.getURLType() == 2 ? urlInfoBean.getThum() : urlInfoBean.getURL();
            this.mVideoUrl = urlInfoBean.getURL();
            this.urlType = urlInfoBean.getURLType() == 2 ? 1 : 0;
        }
    }

    public TextureView createTextureView() {
        TextureView textureView = newTextureView();
        FrameLayout.LayoutParams params = new FrameLayout.LayoutParams(-1, -1, 17);
        textureView.setLayoutParams(params);
        return textureView;
    }

    protected TextureView newTextureView() {
        return new TextureView(getContext());
    }

    public void setOnLongClickListener(OnPreviewLongClickListener onPreviewLongClickListener) {
        this.mOnPreviewLongClickListener = onPreviewLongClickListener;
    }

    public void setOnPreviewClickListener(OnPreviewClickListener onPreviewClickListener) {
        this.mOnPreviewClickListener = onPreviewClickListener;
    }

    @Override // java.util.Observer
    public void update(Observable o, final Object arg) {
        if (getContext() == null || !(arg instanceof Message) || this.hashCode != ((Message) arg).getHash() || !this.mVideoUrl.equals(((Message) arg).getVideoUrl()) || (arg instanceof DurationMessage) || (arg instanceof BackPressedMessage) || !(arg instanceof UIStateMessage)) {
            return;
        }
        ((Activity) getContext()).runOnUiThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.AlbumPreviewFragment.6
            @Override // java.lang.Runnable
            public void run() {
                AlbumPreviewFragment.this.onChangeUIState(((UIStateMessage) arg).getState());
            }
        });
    }

    public void onChangeUIState(int state) {
        if (state != 0) {
            if (state != 1) {
                if (state != 2 && state != 4 && state != 5) {
                    if (state != 6) {
                        throw new IllegalStateException("Illegal Play State:" + state);
                    }
                }
            }
            this.mLoading.setVisibility(0);
            return;
        }
        this.mLoading.setVisibility(8);
    }
}
