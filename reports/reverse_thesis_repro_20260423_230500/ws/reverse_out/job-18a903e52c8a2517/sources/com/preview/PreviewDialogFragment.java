package com.preview;

import android.content.Context;
import android.graphics.drawable.ColorDrawable;
import android.graphics.drawable.Drawable;
import android.os.Build;
import android.os.Bundle;
import android.util.Log;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.view.ViewParent;
import android.view.Window;
import android.view.WindowManager;
import android.widget.AbsListView;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.RelativeLayout;
import android.widget.TextView;
import androidx.appcompat.app.AppCompatActivity;
import androidx.fragment.app.DialogFragment;
import androidx.fragment.app.FragmentActivity;
import androidx.fragment.app.FragmentManager;
import androidx.recyclerview.widget.RecyclerView;
import androidx.viewpager.widget.ViewPager;
import com.preview.PhotoPreviewFragment;
import com.preview.PhotoPreviewPagerAdapter;
import com.preview.interfaces.ImageLoader;
import com.preview.interfaces.OnDismissListener;
import com.preview.interfaces.OnLongClickListener;
import com.preview.util.Utils;
import com.preview.util.notch.NotchAdapterUtils;
import java.util.List;
import java.util.UUID;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes2.dex */
public class PreviewDialogFragment extends DialogFragment {
    private PhotoPreviewPagerAdapter adapter;
    private FrameLayout flViewpagerContainer;
    private FragmentActivity mActivity;
    private Context mContext;
    private int mDefaultShowPosition;
    private ImageLoader mImageLoader;
    private ImageView mIvSelectDot;
    private LinearLayout mLlDotIndicator;
    private OnLongClickListener mLongClickListener;
    private OnDismissListener mOnDismissListener;
    private List<?> mPicUrls;
    private Integer mProgressColor;
    private Drawable mProgressDrawable;
    private RelativeLayout mRootView;
    private View mSrcImageContainer;
    private TextView mTvTextIndicator;
    private ViewPager mViewPager;
    private String timeStr;
    private RelativeLayout title;
    private TextView txt_time;
    private String tag = UUID.randomUUID().toString();
    private int mCurrentPagerIndex = 0;
    private int mIndicatorType = 0;
    private long mDelayShowProgressTime = 100;

    public PreviewDialogFragment() {
        setCancelable(false);
    }

    @Override // androidx.fragment.app.DialogFragment, androidx.fragment.app.Fragment
    public void onAttach(Context context) {
        super.onAttach(context);
        this.mContext = context;
    }

    @Override // androidx.fragment.app.Fragment
    public void onActivityCreated(Bundle savedInstanceState) {
        if (savedInstanceState != null) {
            super.onActivityCreated(savedInstanceState);
            return;
        }
        boolean fullScreen = (this.mActivity.getWindow().getAttributes().flags & 1024) != 0;
        Window window = getDialog().getWindow();
        if (fullScreen) {
            NotchAdapterUtils.adapter(window, 1);
        }
        if (window != null) {
            window.requestFeature(1);
        }
        super.onActivityCreated(null);
        if (window != null) {
            window.setBackgroundDrawable(new ColorDrawable(0));
            if (Build.VERSION.SDK_INT >= 21) {
                window.setStatusBarColor(-16777216);
            }
            WindowManager.LayoutParams lp = window.getAttributes();
            lp.dimAmount = 0.0f;
            lp.flags |= 2;
            if (fullScreen) {
                lp.flags |= 1024;
            }
            lp.width = -1;
            lp.height = -1;
            window.setAttributes(lp);
            window.getDecorView().setPadding(0, 0, 0, 0);
        }
    }

    @Override // androidx.fragment.app.Fragment
    public View onCreateView(LayoutInflater inflater, ViewGroup container, Bundle savedInstanceState) {
        if (this.mRootView == null) {
            RelativeLayout relativeLayout = (RelativeLayout) inflater.inflate(R.layout.view_preview_root, (ViewGroup) null);
            this.mRootView = relativeLayout;
            this.title = (RelativeLayout) relativeLayout.findViewById(R.attr.title);
            this.flViewpagerContainer = (FrameLayout) this.mRootView.findViewById(R.attr.fl_viewpager_container);
            this.mLlDotIndicator = (LinearLayout) this.mRootView.findViewById(R.attr.ll_dot_indicator_photo_preview);
            this.mIvSelectDot = (ImageView) this.mRootView.findViewById(R.attr.iv_select_dot_photo_preview);
            this.mTvTextIndicator = (TextView) this.mRootView.findViewById(R.attr.tv_text_indicator_photo_preview);
            ImageView iv_back = (ImageView) this.mRootView.findViewById(R.attr.iv_back);
            ImageView img_menu = (ImageView) this.mRootView.findViewById(R.attr.img_menu);
            TextView textView = (TextView) this.mRootView.findViewById(R.attr.txt_time);
            this.txt_time = textView;
            textView.setText(this.timeStr);
            iv_back.setOnClickListener(new View.OnClickListener() { // from class: com.preview.PreviewDialogFragment.1
                @Override // android.view.View.OnClickListener
                public void onClick(View v) {
                    PhotoPreviewFragment currentFragment;
                    if (PreviewDialogFragment.this.mViewPager != null && PreviewDialogFragment.this.mViewPager.getAdapter() != null && (PreviewDialogFragment.this.mViewPager.getAdapter() instanceof PhotoPreviewPagerAdapter) && (currentFragment = ((PhotoPreviewPagerAdapter) PreviewDialogFragment.this.mViewPager.getAdapter()).getCurrentFragment()) != null) {
                        currentFragment.exit();
                    }
                }
            });
            img_menu.setOnClickListener(new View.OnClickListener() { // from class: com.preview.PreviewDialogFragment.2
                @Override // android.view.View.OnClickListener
                public void onClick(View v) {
                    if (PreviewDialogFragment.this.mLongClickListener != null) {
                        PreviewDialogFragment.this.mLongClickListener.onLongClick(null, PreviewDialogFragment.this.mPicUrls.get(PreviewDialogFragment.this.mCurrentPagerIndex), PreviewDialogFragment.this.mCurrentPagerIndex);
                    }
                }
            });
        }
        if (savedInstanceState == null) {
            initViewData();
        } else {
            dismiss();
        }
        return this.mRootView;
    }

    private void initViewData() {
        this.mLlDotIndicator.setVisibility(8);
        this.mIvSelectDot.setVisibility(8);
        this.mTvTextIndicator.setVisibility(8);
        prepareIndicator();
        prepareViewPager();
    }

    public void setTitle(String time) {
        this.timeStr = time;
        StringBuilder sb = new StringBuilder();
        sb.append("=====");
        sb.append(this.txt_time != null);
        sb.append("   ");
        sb.append(this.timeStr);
        Log.d("------", sb.toString());
        TextView textView = this.txt_time;
        if (textView != null) {
            textView.setText(this.timeStr);
        }
    }

    public void setActivity(AppCompatActivity activity) {
        this.mActivity = activity;
    }

    public void setActivity(FragmentActivity activity) {
        this.mActivity = activity;
    }

    public void setImageLoader(ImageLoader imageLoader) {
        this.mImageLoader = imageLoader;
    }

    public void setIsShowTitle(boolean isShowTitle) {
        RelativeLayout relativeLayout = this.title;
        if (relativeLayout != null) {
            relativeLayout.setVisibility(isShowTitle ? 0 : 8);
        }
    }

    public void setLongClickListener(OnLongClickListener longClickListener) {
        this.mLongClickListener = longClickListener;
    }

    public void setOnDismissListener(OnDismissListener onDismissListener) {
        this.mOnDismissListener = onDismissListener;
    }

    public void setIndicatorType(int indicatorType) {
        this.mIndicatorType = indicatorType;
    }

    public void setDelayShowProgressTime(long delayShowProgressTime) {
        this.mDelayShowProgressTime = delayShowProgressTime;
    }

    public void setProgressColor(int progressColor) {
        this.mProgressColor = Integer.valueOf(progressColor);
    }

    public void setProgressDrawable(Drawable progressDrawable) {
        this.mProgressDrawable = progressDrawable;
    }

    public void show(View srcImageContainer, int defaultShowPosition, List<?> picUrls) {
        this.mSrcImageContainer = srcImageContainer;
        this.mPicUrls = picUrls;
        this.mDefaultShowPosition = defaultShowPosition;
        this.mCurrentPagerIndex = defaultShowPosition;
        FragmentManager manager = this.mActivity.getSupportFragmentManager();
        if (isAdded() || manager.findFragmentByTag(this.tag) != null) {
            initViewData();
        } else {
            show(manager, this.tag);
        }
    }

    private void prepareViewPager() {
        if (this.mViewPager == null) {
            this.mViewPager = new NoTouchExceptionViewPager(this.mContext);
            FrameLayout.LayoutParams params = new FrameLayout.LayoutParams(-1, -1);
            this.mViewPager.setLayoutParams(params);
            ViewPager viewPager = this.mViewPager;
            viewPager.setId(viewPager.hashCode());
            this.flViewpagerContainer.addView(this.mViewPager);
        }
        if (this.mViewPager.getAdapter() == null) {
            PhotoPreviewPagerAdapter photoPreviewPagerAdapter = new PhotoPreviewPagerAdapter(getChildFragmentManager(), this.mPicUrls.size());
            this.adapter = photoPreviewPagerAdapter;
            photoPreviewPagerAdapter.setFragmentOnExitListener(new PhotoPreviewFragment.OnExitListener() { // from class: com.preview.PreviewDialogFragment.3
                @Override // com.preview.PhotoPreviewFragment.OnExitListener
                public void onStart() {
                    PreviewDialogFragment.this.mLlDotIndicator.setVisibility(8);
                    PreviewDialogFragment.this.mIvSelectDot.setVisibility(8);
                    PreviewDialogFragment.this.mTvTextIndicator.setVisibility(8);
                }

                @Override // com.preview.PhotoPreviewFragment.OnExitListener
                public void onExit() {
                    PreviewDialogFragment.this.dismissAllowingStateLoss();
                    PreviewDialogFragment.this.flViewpagerContainer.removeView(PreviewDialogFragment.this.mViewPager);
                    PreviewDialogFragment.this.mViewPager = null;
                    ViewParent parent = PreviewDialogFragment.this.mRootView.getParent();
                    if (parent instanceof ViewGroup) {
                        ((ViewGroup) parent).removeView(PreviewDialogFragment.this.mRootView);
                    }
                    if (PreviewDialogFragment.this.mOnDismissListener != null) {
                        PreviewDialogFragment.this.mOnDismissListener.onDismiss();
                    }
                }
            });
            this.mViewPager.setAdapter(this.adapter);
            this.mViewPager.addOnPageChangeListener(new ViewPager.OnPageChangeListener() { // from class: com.preview.PreviewDialogFragment.4
                @Override // androidx.viewpager.widget.ViewPager.OnPageChangeListener
                public void onPageScrolled(int position, float positionOffset, int positionOffsetPixels) {
                    if (PreviewDialogFragment.this.mLlDotIndicator.getVisibility() == 0) {
                        float dx = PreviewDialogFragment.this.mLlDotIndicator.getChildAt(1).getX() - PreviewDialogFragment.this.mLlDotIndicator.getChildAt(0).getX();
                        PreviewDialogFragment.this.mIvSelectDot.setTranslationX((position * dx) + (positionOffset * dx));
                    }
                }

                @Override // androidx.viewpager.widget.ViewPager.OnPageChangeListener
                public void onPageSelected(int position) {
                    PreviewDialogFragment.this.mCurrentPagerIndex = position;
                    if (PreviewDialogFragment.this.mTvTextIndicator.getVisibility() == 0) {
                        PreviewDialogFragment.this.mTvTextIndicator.setText((PreviewDialogFragment.this.mCurrentPagerIndex + 1) + " / " + PreviewDialogFragment.this.mPicUrls.size());
                    }
                }

                @Override // androidx.viewpager.widget.ViewPager.OnPageChangeListener
                public void onPageScrollStateChanged(int position) {
                }
            });
        } else {
            PhotoPreviewPagerAdapter photoPreviewPagerAdapter2 = (PhotoPreviewPagerAdapter) this.mViewPager.getAdapter();
            this.adapter = photoPreviewPagerAdapter2;
            photoPreviewPagerAdapter2.setData(this.mPicUrls.size());
        }
        this.adapter.setOnUpdateFragmentDataListener(new PhotoPreviewPagerAdapter.OnUpdateFragmentDataListener() { // from class: com.preview.PreviewDialogFragment.5
            @Override // com.preview.PhotoPreviewPagerAdapter.OnUpdateFragmentDataListener
            public void onUpdate(PhotoPreviewFragment fragment, int position) {
                boolean fullScreen = (PreviewDialogFragment.this.mActivity.getWindow().getAttributes().flags & 1024) != 0;
                fragment.setData(PreviewDialogFragment.this.mImageLoader, position, PreviewDialogFragment.this.mPicUrls.get(position), PreviewDialogFragment.this.getViewSize(position), PreviewDialogFragment.this.getViewLocation(position), position == PreviewDialogFragment.this.mDefaultShowPosition, PreviewDialogFragment.this.mDelayShowProgressTime, PreviewDialogFragment.this.mProgressColor, PreviewDialogFragment.this.mProgressDrawable, fullScreen);
                fragment.setOnLongClickListener(PreviewDialogFragment.this.mLongClickListener);
            }
        });
        this.mViewPager.setCurrentItem(this.mCurrentPagerIndex);
    }

    private void prepareIndicator() {
        if (this.mIndicatorType == -1) {
            this.mLlDotIndicator.setVisibility(8);
            this.mTvTextIndicator.setVisibility(8);
            return;
        }
        if (this.mPicUrls.size() >= 2 && this.mPicUrls.size() <= 9) {
            if (this.mIndicatorType == 0) {
                this.mLlDotIndicator.removeAllViews();
                final LinearLayout.LayoutParams dotParams = new LinearLayout.LayoutParams(-2, -2);
                dotParams.rightMargin = Utils.dp2px(this.mContext, 12);
                for (int i = 0; i < this.mPicUrls.size(); i++) {
                    ImageView iv = new ImageView(this.mContext);
                    iv.setImageDrawable(this.mContext.getResources().getDrawable(R.drawable.no_selected_dot));
                    iv.setLayoutParams(dotParams);
                    this.mLlDotIndicator.addView(iv);
                }
                this.mLlDotIndicator.post(new Runnable() { // from class: com.preview.PreviewDialogFragment.6
                    @Override // java.lang.Runnable
                    public void run() {
                        RelativeLayout.LayoutParams params = (RelativeLayout.LayoutParams) PreviewDialogFragment.this.mIvSelectDot.getLayoutParams();
                        params.leftMargin = (int) PreviewDialogFragment.this.mLlDotIndicator.getChildAt(0).getX();
                        PreviewDialogFragment.this.mIvSelectDot.setTranslationX((dotParams.rightMargin * PreviewDialogFragment.this.mCurrentPagerIndex) + (PreviewDialogFragment.this.mLlDotIndicator.getChildAt(0).getWidth() * PreviewDialogFragment.this.mCurrentPagerIndex));
                        PreviewDialogFragment.this.mIvSelectDot.setVisibility(0);
                    }
                });
                this.mLlDotIndicator.setVisibility(0);
                return;
            }
            this.mTvTextIndicator.setVisibility(0);
            this.mTvTextIndicator.setText((this.mCurrentPagerIndex + 1) + "/" + this.mPicUrls.size());
            return;
        }
        if (this.mPicUrls.size() > 9) {
            this.mTvTextIndicator.setVisibility(0);
            this.mTvTextIndicator.setText((this.mCurrentPagerIndex + 1) + "/" + this.mPicUrls.size());
        }
    }

    private View getItemView(int position) {
        RecyclerView.LayoutManager layoutManager;
        View view = this.mSrcImageContainer;
        if (!(view instanceof ViewGroup)) {
            return view;
        }
        if (view instanceof AbsListView) {
            return ((AbsListView) view).getChildAt(position);
        }
        if (!(view instanceof RecyclerView) || (layoutManager = ((RecyclerView) view).getLayoutManager()) == null) {
            return null;
        }
        return layoutManager.findViewByPosition(position);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public int[] getViewSize(int position) {
        int[] result = new int[2];
        View itemView = getItemView(position);
        if (itemView == null) {
            int i = this.mDefaultShowPosition;
            if (position != i) {
                return getViewSize(i);
            }
            return result;
        }
        result[0] = itemView.getMeasuredWidth();
        result[1] = itemView.getMeasuredHeight();
        return result;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public int[] getViewLocation(int position) {
        int[] result = new int[2];
        View itemView = getItemView(position);
        if (itemView == null) {
            int i = this.mDefaultShowPosition;
            if (position != i) {
                return getViewLocation(i);
            }
            return result;
        }
        itemView.getLocationOnScreen(result);
        result[0] = result[0] + (itemView.getMeasuredWidth() / 2);
        result[1] = result[1] + (itemView.getMeasuredHeight() / 2);
        return result;
    }
}
