package im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui;

import android.animation.ObjectAnimator;
import android.graphics.Color;
import android.graphics.drawable.Drawable;
import android.graphics.drawable.GradientDrawable;
import android.net.Uri;
import android.text.TextUtils;
import android.view.View;
import android.view.ViewGroup;
import android.view.ViewParent;
import android.view.WindowManager;
import android.widget.FrameLayout;
import android.widget.LinearLayout;
import android.widget.TextView;
import androidx.core.content.ContextCompat;
import androidx.fragment.app.Fragment;
import androidx.fragment.app.FragmentManager;
import androidx.viewpager.widget.ViewPager;
import com.bjz.comm.net.bean.BResponseNoData;
import com.bjz.comm.net.bean.UrlInfoBean;
import com.bjz.comm.net.factory.ApiFactory;
import com.bjz.comm.net.mvp.contract.BaseFcContract;
import com.bjz.comm.net.mvp.presenter.FcCommonPresenter;
import com.bjz.comm.net.utils.JsonCreateUtils;
import com.bjz.comm.net.utils.RxHelper;
import com.preview.BaseFragmentPagerAdapter;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.ui.actionbar.ActionBar;
import im.uwrkaxlmjj.ui.actionbar.AlertDialog;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.dialogs.FcDialog;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.base.CommFcActivity;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.listener.OnPreviewClickListener;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.listener.OnPreviewLongClickListener;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.player.player.VideoPlayerManager;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.utils.FcDialogUtil;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.utils.TimeUtils;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.FcCommMenuDialog;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.toast.FcToastUtils;
import io.reactivex.Observable;
import io.reactivex.functions.Consumer;
import java.io.File;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import mpEIGo.juqQQs.esbSDO.R;
import okhttp3.RequestBody;

/* JADX INFO: loaded from: classes5.dex */
public class AlbumPreviewActivity extends CommFcActivity implements BaseFcContract.IFcCommView {
    private static final String TAG = AlbumPreviewActivity.class.getSimpleName();
    private int currentIndex;
    private FragmentManager fragmentManager;
    private LinearLayout ll_title;
    private MyFragmentPagerAdapter mAdapter;
    private FcCommonPresenter mFcCommonPresenter;
    private OnDeleteDelegate mOnDeleteDelegate;
    private ViewPager mVpContent;
    private AlertDialog progressDialog;
    private TextView tv_title;
    private List<UrlInfoBean> urlInfoBeanList = new ArrayList();

    public interface OnDeleteDelegate {
        void onDelete(long j, int i);
    }

    public AlbumPreviewActivity(List<UrlInfoBean> urlInfoBeanList, int currentIndex) {
        this.currentIndex = 0;
        if (urlInfoBeanList != null && urlInfoBeanList.size() > 0) {
            this.currentIndex = currentIndex;
            this.urlInfoBeanList.clear();
            this.urlInfoBeanList.addAll(urlInfoBeanList);
        }
    }

    public void setOnDeleteDelegate(OnDeleteDelegate onDeleteDelegate) {
        this.mOnDeleteDelegate = onDeleteDelegate;
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public boolean onFragmentCreate() {
        this.mFcCommonPresenter = new FcCommonPresenter(this);
        return super.onFragmentCreate();
    }

    @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.base.BaseFcActivity
    protected int getLayoutRes() {
        return R.layout.activity_albums_preview;
    }

    @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.base.BaseFcActivity
    protected void initView() {
        List<UrlInfoBean> list;
        UrlInfoBean bean;
        this.actionBar.setVisibility(8);
        final FrameLayout mRootView = (FrameLayout) this.fragmentView.findViewById(R.attr.root_view);
        this.ll_title = (LinearLayout) this.fragmentView.findViewById(R.attr.ll_title);
        this.tv_title = (TextView) this.fragmentView.findViewById(R.attr.tv_title);
        this.fragmentView.findViewById(R.attr.iv_back).setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.AlbumPreviewActivity.1
            @Override // android.view.View.OnClickListener
            public void onClick(View v) {
                mRootView.removeView(AlbumPreviewActivity.this.mVpContent);
                AlbumPreviewActivity.this.mVpContent = null;
                ViewParent parent = mRootView.getParent();
                if (parent instanceof ViewGroup) {
                    ((ViewGroup) parent).removeView(mRootView);
                }
                AlbumPreviewActivity.this.finishFragment();
            }
        });
        this.mVpContent = (ViewPager) this.fragmentView.findViewById(R.attr.vp_preview_fragment);
        this.fragmentManager = getParentActivity().getSupportFragmentManager();
        ViewPager viewPager = this.mVpContent;
        viewPager.setId(viewPager.hashCode());
        MyFragmentPagerAdapter myFragmentPagerAdapter = new MyFragmentPagerAdapter(this.fragmentManager, this.urlInfoBeanList.size());
        this.mAdapter = myFragmentPagerAdapter;
        myFragmentPagerAdapter.setOnUpdateFragmentDataListener(new MyFragmentPagerAdapter.OnUpdateFragmentDataListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.AlbumPreviewActivity.2
            @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.AlbumPreviewActivity.MyFragmentPagerAdapter.OnUpdateFragmentDataListener
            public void onUpdate(AlbumPreviewFragment fragment, int position) {
                fragment.setData((UrlInfoBean) AlbumPreviewActivity.this.urlInfoBeanList.get(position), position);
                fragment.setOnLongClickListener(new OnPreviewLongClickListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.AlbumPreviewActivity.2.1
                    @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.listener.OnPreviewLongClickListener
                    public void onLongClick(UrlInfoBean urlInfoBean, int position2) {
                        AlbumPreviewActivity.this.showMenuDialog(urlInfoBean, position2);
                    }
                });
                fragment.setOnPreviewClickListener(new OnPreviewClickListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.AlbumPreviewActivity.2.2
                    @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.listener.OnPreviewClickListener
                    public void onClick() {
                        AlbumPreviewActivity.this.controlTitleVisible();
                    }
                });
            }
        });
        this.mVpContent.setAdapter(this.mAdapter);
        this.mVpContent.addOnPageChangeListener(new ViewPager.OnPageChangeListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.AlbumPreviewActivity.3
            @Override // androidx.viewpager.widget.ViewPager.OnPageChangeListener
            public void onPageScrolled(int position, float positionOffset, int positionOffsetPixels) {
            }

            @Override // androidx.viewpager.widget.ViewPager.OnPageChangeListener
            public void onPageSelected(int position) {
                UrlInfoBean bean2;
                if (AlbumPreviewActivity.this.urlInfoBeanList != null && position < AlbumPreviewActivity.this.urlInfoBeanList.size() && AlbumPreviewActivity.this.tv_title != null && (bean2 = (UrlInfoBean) AlbumPreviewActivity.this.urlInfoBeanList.get(position)) != null) {
                    long createTime = bean2.getCreateTime();
                    if (createTime > 0) {
                        AlbumPreviewActivity.this.tv_title.setText(TimeUtils.fcFormat2Date(createTime));
                    }
                }
                AlbumPreviewActivity.this.currentIndex = position;
            }

            @Override // androidx.viewpager.widget.ViewPager.OnPageChangeListener
            public void onPageScrollStateChanged(int position) {
            }
        });
        int i = this.currentIndex;
        if (i == 0 && (list = this.urlInfoBeanList) != null && i < list.size() && (bean = this.urlInfoBeanList.get(this.currentIndex)) != null) {
            long createTime = bean.getCreateTime();
            if (createTime > 0) {
                this.tv_title.setText(TimeUtils.fcFormat2Date(createTime));
            }
        }
    }

    @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.base.BaseFcActivity
    protected void initData() {
        this.mVpContent.setCurrentItem(this.currentIndex);
    }

    protected void showMenuDialog(final UrlInfoBean urlInfoBean, final int clickPosition) {
        int urlType = urlInfoBean.getURLType();
        String tips = LocaleController.getString("save_pic", R.string.save_pic);
        String suffix = ".jpg";
        if (urlType == 1) {
            tips = LocaleController.getString("save_pic", R.string.save_pic);
            suffix = ".jpg";
        } else if (urlType == 2) {
            tips = LocaleController.getString("save_video", R.string.save_video);
            suffix = ".mp4";
        } else if (urlType == 3) {
            tips = LocaleController.getString("save_pic", R.string.save_pic);
            suffix = ".gif";
        }
        List<String> list = new ArrayList<>();
        list.add(tips);
        list.add(LocaleController.getString("Delete", R.string.Delete));
        int[] colors = {Theme.getColor(Theme.key_dialogTextBlack), ContextCompat.getColor(this.mContext, R.color.color_item_menu_red_f74c31)};
        final String finalSuffix = suffix;
        FcCommMenuDialog dialogCommonList = new FcCommMenuDialog(getParentActivity(), list, (List<Integer>) null, colors, new FcCommMenuDialog.RecyclerviewItemClickCallBack() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.AlbumPreviewActivity.4
            @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.view.FcCommMenuDialog.RecyclerviewItemClickCallBack
            public void onRecyclerviewItemClick(int position) {
                if (position == 0) {
                    AlbumPreviewActivity.this.showProgress();
                    AlbumPreviewActivity.this.mFcCommonPresenter.downloadFile(urlInfoBean.getURL(), AndroidUtilities.getAlbumDir(false).getAbsolutePath(), TimeUtils.getCurrentTime() + finalSuffix);
                    return;
                }
                if (position == 1) {
                    AlbumPreviewActivity.this.showDeleteDialog(urlInfoBean, clickPosition);
                }
            }
        }, 1);
        dialogCommonList.show();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void showDeleteDialog(UrlInfoBean urlInfoBean, final int position) {
        boolean hasSameGroup;
        if (urlInfoBean != null) {
            final long forumID = urlInfoBean.getForumID();
            int urlType = urlInfoBean.getURLType();
            final ArrayList<UrlInfoBean> deleteList = new ArrayList<>();
            if (urlType == 1) {
                for (UrlInfoBean bean : this.urlInfoBeanList) {
                    if (bean != null && bean.getForumID() == forumID) {
                        deleteList.add(bean);
                    }
                }
            }
            if (deleteList.size() <= 1) {
                hasSameGroup = false;
            } else {
                hasSameGroup = true;
            }
            FcDialogUtil.showDeleteAlbumItemDialog(this, urlType, hasSameGroup, new FcDialog.OnConfirmClickListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.-$$Lambda$AlbumPreviewActivity$K2NpDDUdCdmrpFFgfYiBcwrr4sQ
                @Override // im.uwrkaxlmjj.ui.dialogs.FcDialog.OnConfirmClickListener
                public final void onClick(View view) {
                    this.f$0.lambda$showDeleteDialog$0$AlbumPreviewActivity(forumID, deleteList, position, view);
                }
            }, null);
        }
    }

    public /* synthetic */ void lambda$showDeleteDialog$0$AlbumPreviewActivity(long forumID, ArrayList deleteList, int position, View dialog) {
        doDeleteFc(forumID, deleteList, position);
    }

    private void doDeleteFc(final long forumID, final ArrayList<UrlInfoBean> deleteList, final int position) {
        showProgress();
        RequestBody requestBody = JsonCreateUtils.build().addParam("ForumID", Long.valueOf(forumID)).getHttpBody();
        Observable<BResponseNoData> observable = ApiFactory.getInstance().getApiMomentForum().doDeleteItem(requestBody);
        RxHelper.getInstance().sendRequestNoData(TAG, observable, new Consumer<BResponseNoData>() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.AlbumPreviewActivity.5
            @Override // io.reactivex.functions.Consumer
            public void accept(BResponseNoData responseNoData) throws Exception {
                AlbumPreviewActivity.this.hideProgress();
                if (responseNoData != null) {
                    if (responseNoData.isState()) {
                        ArrayList arrayList = deleteList;
                        if (arrayList == null || arrayList.size() <= 0) {
                            AlbumPreviewActivity.this.urlInfoBeanList.remove(position);
                            AlbumPreviewActivity.this.mAdapter.setData(AlbumPreviewActivity.this.urlInfoBeanList.size());
                            if (AlbumPreviewActivity.this.mOnDeleteDelegate != null) {
                                AlbumPreviewActivity.this.mOnDeleteDelegate.onDelete(forumID, position);
                            }
                            if (AlbumPreviewActivity.this.urlInfoBeanList.size() == 0) {
                                AlbumPreviewActivity.this.finishFragment();
                            }
                        } else {
                            Iterator<UrlInfoBean> iterator = AlbumPreviewActivity.this.urlInfoBeanList.iterator();
                            while (iterator.hasNext()) {
                                UrlInfoBean next = iterator.next();
                                if (next.getForumID() == forumID) {
                                    iterator.remove();
                                }
                            }
                            AlbumPreviewActivity.this.mAdapter.setData(AlbumPreviewActivity.this.urlInfoBeanList.size());
                            if (AlbumPreviewActivity.this.mOnDeleteDelegate != null) {
                                AlbumPreviewActivity.this.mOnDeleteDelegate.onDelete(forumID, position);
                            }
                            if (AlbumPreviewActivity.this.urlInfoBeanList.size() == 0) {
                                AlbumPreviewActivity.this.finishFragment();
                            }
                        }
                    }
                    AlbumPreviewActivity.this.showTipsDialog(LocaleController.getString(R.string.deleted_succ));
                    return;
                }
                FcToastUtils.show(R.string.deleted_fail);
            }
        }, new Consumer<Throwable>() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.AlbumPreviewActivity.6
            @Override // io.reactivex.functions.Consumer
            public void accept(Throwable throwable) throws Exception {
                AlbumPreviewActivity.this.hideProgress();
                FcToastUtils.show((CharSequence) RxHelper.getInstance().getErrorInfo(throwable));
            }
        });
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void controlTitleVisible() {
        LinearLayout linearLayout = this.ll_title;
        if (linearLayout != null) {
            if (linearLayout.getVisibility() == 0) {
                hideTitle();
            } else {
                showTitle();
            }
        }
    }

    public void hideTitle() {
        ObjectAnimator animator = ObjectAnimator.ofFloat(this.ll_title, "translationY", 0.0f, -ActionBar.getCurrentActionBarHeight());
        animator.setDuration(300L);
        animator.start();
        this.ll_title.setVisibility(8);
    }

    public void showTitle() {
        ObjectAnimator animator = ObjectAnimator.ofFloat(this.ll_title, "translationY", -ActionBar.getCurrentActionBarHeight(), 0.0f);
        animator.setDuration(300L);
        animator.start();
        this.ll_title.setVisibility(0);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void showProgress() {
        if (this.progressDialog == null) {
            this.progressDialog = new AlertDialog(getParentActivity(), 3);
        }
        if (!this.progressDialog.isShowing()) {
            this.progressDialog.show();
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void hideProgress() {
        AlertDialog alertDialog = this.progressDialog;
        if (alertDialog != null && alertDialog.isShowing()) {
            this.progressDialog.dismiss();
        }
    }

    @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.base.BaseFcActivity, im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onFragmentDestroy() {
        super.onFragmentDestroy();
        List<UrlInfoBean> list = this.urlInfoBeanList;
        if (list != null) {
            list.clear();
            this.urlInfoBeanList = null;
        }
        VideoPlayerManager.getInstance().release();
        FcCommonPresenter fcCommonPresenter = this.mFcCommonPresenter;
        if (fcCommonPresenter != null) {
            fcCommonPresenter.unSubscribeTask();
        }
    }

    @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.base.BaseFcActivity, com.bjz.comm.net.mvp.contract.BaseFcContract.IFcCommView
    public void onDownloadFileSucc(File file) {
        hideProgress();
        AndroidUtilities.addMediaToGallery(Uri.fromFile(file));
        showTipsDialog(LocaleController.getString(R.string.save_album_success));
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void showTipsDialog(String content) {
        if (TextUtils.isEmpty(content)) {
            return;
        }
        try {
            final WindowManager windowManager = (WindowManager) this.mContext.getSystemService("window");
            WindowManager.LayoutParams para = new WindowManager.LayoutParams();
            para.height = AndroidUtilities.dp(133.0f);
            para.width = AndroidUtilities.dp(133.0f);
            para.flags = 24;
            para.format = -2;
            para.type = 2005;
            para.gravity = 17;
            final FrameLayout frameLayout = new FrameLayout(this.mContext);
            GradientDrawable gradientDrawable = new GradientDrawable();
            gradientDrawable.setShape(0);
            gradientDrawable.setCornerRadius(11.0f);
            gradientDrawable.setColor(Color.parseColor("#8C000000"));
            frameLayout.setBackground(gradientDrawable);
            TextView tv_tips = new TextView(this.mContext);
            FrameLayout.LayoutParams layoutParams = new FrameLayout.LayoutParams(-2, -2);
            layoutParams.gravity = 17;
            tv_tips.setLayoutParams(layoutParams);
            tv_tips.setGravity(17);
            tv_tips.setTextAlignment(4);
            tv_tips.setTextColor(-1);
            tv_tips.setTextSize(16.0f);
            tv_tips.setText(content);
            Drawable drawable = this.mContext.getResources().getDrawable(R.id.ic_album_tips_success);
            drawable.setBounds(0, 0, drawable.getMinimumWidth(), drawable.getMinimumHeight());
            tv_tips.setCompoundDrawables(null, drawable, null, null);
            tv_tips.setCompoundDrawablePadding(AndroidUtilities.dp(20.0f));
            frameLayout.addView(tv_tips);
            windowManager.addView(frameLayout, para);
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.AlbumPreviewActivity.7
                @Override // java.lang.Runnable
                public void run() {
                    windowManager.removeView(frameLayout);
                }
            }, 1800L);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.base.BaseFcActivity, com.bjz.comm.net.mvp.contract.BaseFcContract.IFcCommView
    public void onDownloadFileError(String msg) {
        hideProgress();
        FcToastUtils.show((CharSequence) LocaleController.getString(R.string.save_album_error));
    }

    @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.base.BaseFcActivity, com.bjz.comm.net.mvp.contract.BaseFcContract.IFcCommView
    public void onError(String msg) {
    }

    private static class MyFragmentPagerAdapter extends BaseFragmentPagerAdapter {
        private OnUpdateFragmentDataListener mOnUpdateFragmentDataListener;
        private int size;

        public interface OnUpdateFragmentDataListener {
            void onUpdate(AlbumPreviewFragment albumPreviewFragment, int i);
        }

        public MyFragmentPagerAdapter(FragmentManager fm, int size) {
            super(fm);
            this.size = size;
        }

        @Override // com.preview.BaseFragmentPagerAdapter
        public Fragment getItem(int position) {
            AlbumPreviewFragment fragment = new AlbumPreviewFragment();
            return fragment;
        }

        @Override // com.preview.BaseFragmentPagerAdapter, androidx.viewpager.widget.PagerAdapter
        public Object instantiateItem(ViewGroup container, int position) {
            OnUpdateFragmentDataListener onUpdateFragmentDataListener;
            Object item = super.instantiateItem(container, position);
            if ((item instanceof AlbumPreviewFragment) && (onUpdateFragmentDataListener = this.mOnUpdateFragmentDataListener) != null) {
                onUpdateFragmentDataListener.onUpdate((AlbumPreviewFragment) item, position);
            }
            return item;
        }

        @Override // com.preview.BaseFragmentPagerAdapter
        public boolean dataIsChange(Object object) {
            return true;
        }

        @Override // androidx.viewpager.widget.PagerAdapter
        public int getCount() {
            return this.size;
        }

        public void setOnUpdateFragmentDataListener(OnUpdateFragmentDataListener onUpdateFragmentDataListener) {
            this.mOnUpdateFragmentDataListener = onUpdateFragmentDataListener;
        }

        public void setData(int size) {
            this.size = size;
            notifyDataSetChanged();
        }
    }
}
