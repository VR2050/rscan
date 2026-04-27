package im.uwrkaxlmjj.ui.hui.friendscircle_v1;

import android.graphics.Color;
import android.os.Bundle;
import android.text.TextUtils;
import android.util.LruCache;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import androidx.fragment.app.Fragment;
import androidx.viewpager.widget.ViewPager;
import butterknife.BindView;
import com.bjz.comm.net.bean.BResponse;
import com.bjz.comm.net.bean.FcVersionBean;
import com.bjz.comm.net.utils.AppPreferenceUtil;
import com.bjz.comm.net.utils.RxHelper;
import com.google.gson.Gson;
import com.tablayout.SlidingTabLayout;
import im.uwrkaxlmjj.javaBean.fc.PublishFcBean;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.messenger.MediaController;
import im.uwrkaxlmjj.messenger.NotificationCenter;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.adapters.BaseVPAdapter;
import im.uwrkaxlmjj.ui.fragments.BaseFmts;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.base.CommFcListFragment;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.base.LazyLoadFragment;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.fcInterface.FcPageListRefreshListener;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.fragments.FcFollowFragment;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.fragments.FcHomeFragment;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.fragments.FcRecommendFragment;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.FcPublishActivity;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.ImagePreSelectorActivity;
import im.uwrkaxlmjj.ui.hviews.NoScrollViewPager;
import io.reactivex.Observable;
import java.util.ArrayList;
import java.util.HashMap;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class FriendsCircleFragment extends BaseFmts {
    public static int vipLevel = -1;
    private FcVersionBean fcVersionBean;
    private ImagePreSelectorActivity imageSelectorAlert;
    private OnPageSelectedListener listener;
    private LruCache<Integer, CommFcListFragment> mFragmentCache;
    private Observable<BResponse<FcVersionBean>> observable;

    @BindView(R.attr.tabLayout)
    SlidingTabLayout tabLayout;
    private BaseVPAdapter viewPagerAdapter;

    @BindView(R.attr.viewpager)
    NoScrollViewPager viewpager;
    private int currentSelectedPosition = 0;
    private String TAG = FriendsCircleFragment.class.getSimpleName();
    private FcPageListRefreshListener fcPageListRefreshListener = new FcPageListRefreshListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.FriendsCircleFragment.3
        @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.fcInterface.FcPageListRefreshListener
        public void onRefreshed(int pageIndex) {
            if (FriendsCircleFragment.this.tabLayout != null && pageIndex < FriendsCircleFragment.this.mFragmentCache.size()) {
                FriendsCircleFragment.this.tabLayout.hideMsg(pageIndex);
                if (FriendsCircleFragment.this.fcVersionBean != null) {
                    if (pageIndex == 0) {
                        FriendsCircleFragment.this.fcVersionBean.setRecommendState(false);
                    } else if (pageIndex == 1) {
                        FriendsCircleFragment.this.fcVersionBean.setFriendState(false);
                    } else if (pageIndex == 2) {
                        FriendsCircleFragment.this.fcVersionBean.setFollowState(false);
                    }
                    if (!FriendsCircleFragment.this.fcVersionBean.isFriendState()) {
                        NotificationCenter.getInstance(FriendsCircleFragment.this.currentAccount).postNotificationName(NotificationCenter.userFriendsCircleUpdate, new Object[0]);
                    }
                }
            }
        }

        @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.fcInterface.FcPageListRefreshListener
        public void startFcPublishActivity() {
            startFcPublishActivity();
        }
    };
    private ArrayList<MediaController.PhotoEntry> photoEntries = new ArrayList<>();

    public interface OnPageSelectedListener {
        void onPageSelected(int i);
    }

    public FriendsCircleFragment(OnPageSelectedListener listener) {
        this.listener = listener;
    }

    @Override // im.uwrkaxlmjj.ui.fragments.BaseFmts, androidx.fragment.app.Fragment
    public View onCreateView(LayoutInflater inflater, ViewGroup container, Bundle savedInstanceState) {
        this.fragmentView = LayoutInflater.from(this.context).inflate(R.layout.fragment_friends_ciecle, (ViewGroup) null, false);
        this.fragmentView.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundGray));
        useButterKnife();
        initTabLayout();
        initViewPager();
        loadUserInfo();
        return this.fragmentView;
    }

    @Override // im.uwrkaxlmjj.ui.fragments.BaseFmts
    protected void lazyLoadData() {
        super.lazyLoadData();
        LruCache<Integer, CommFcListFragment> lruCache = this.mFragmentCache;
        if (lruCache != null && lruCache.size() > 0) {
            for (int i = 0; i < this.mFragmentCache.size(); i++) {
                LazyLoadFragment commFcListFragment = this.mFragmentCache.get(Integer.valueOf(i));
                if (commFcListFragment != null && commFcListFragment.isAdded()) {
                    commFcListFragment.checkLoadData();
                }
            }
        }
    }

    @Override // im.uwrkaxlmjj.ui.fragments.BaseFmts
    public void onResumeForBaseFragment() {
        super.onResumeForBaseFragment();
        loadUserInfo();
        LruCache<Integer, CommFcListFragment> lruCache = this.mFragmentCache;
        if (lruCache != null && lruCache.size() > 0) {
            for (int i = 0; i < this.mFragmentCache.size(); i++) {
                LazyLoadFragment commFcListFragment = this.mFragmentCache.get(Integer.valueOf(i));
                if (commFcListFragment != null && commFcListFragment.isAdded()) {
                    commFcListFragment.onResumeForBaseFragment();
                }
            }
        }
    }

    @Override // im.uwrkaxlmjj.ui.fragments.BaseFmts
    public void onPauseForBaseFragment() {
        super.onPauseForBaseFragment();
        LruCache<Integer, CommFcListFragment> lruCache = this.mFragmentCache;
        if (lruCache != null && lruCache.size() > 0) {
            for (int i = 0; i < this.mFragmentCache.size(); i++) {
                LazyLoadFragment commFcListFragment = this.mFragmentCache.get(Integer.valueOf(i));
                if (commFcListFragment != null && commFcListFragment.isAdded()) {
                    commFcListFragment.onPauseForBaseFragment();
                }
            }
        }
    }

    @Override // im.uwrkaxlmjj.ui.fragments.BaseFmts
    public void onVisible() {
        super.onVisible();
        loadUserInfo();
        LruCache<Integer, CommFcListFragment> lruCache = this.mFragmentCache;
        if (lruCache != null && lruCache.size() > 0) {
            for (int i = 0; i < this.mFragmentCache.size(); i++) {
                LazyLoadFragment commFcListFragment = this.mFragmentCache.get(Integer.valueOf(i));
                if (commFcListFragment != null && commFcListFragment.isAdded() && commFcListFragment.isDataLoaded()) {
                    commFcListFragment.onVisible();
                }
            }
        }
    }

    @Override // im.uwrkaxlmjj.ui.fragments.BaseFmts
    public void onInvisible() {
        super.onInvisible();
        LruCache<Integer, CommFcListFragment> lruCache = this.mFragmentCache;
        if (lruCache != null && lruCache.size() > 0) {
            for (int i = 0; i < this.mFragmentCache.size(); i++) {
                LazyLoadFragment commFcListFragment = this.mFragmentCache.get(Integer.valueOf(i));
                if (commFcListFragment != null && commFcListFragment.isAdded()) {
                    commFcListFragment.onInvisible();
                }
            }
        }
    }

    private void loadUserInfo() {
    }

    @Override // im.uwrkaxlmjj.ui.fragments.BaseFmts, androidx.fragment.app.Fragment
    public void onDestroyView() {
        super.onDestroyView();
        getConnectionsManager().cancelRequestsForGuid(this.classGuid);
        vipLevel = -1;
        if (this.observable != null) {
            RxHelper.getInstance().lambda$sendSimpleRequest$0$RxHelper(this.TAG);
            this.observable = null;
        }
        BaseVPAdapter baseVPAdapter = this.viewPagerAdapter;
        if (baseVPAdapter != null) {
            baseVPAdapter.destroy();
            this.viewPagerAdapter = null;
        }
    }

    private void initTabLayout() {
        this.tabLayout.setMsgViewBackgroundColor(Color.parseColor("#FFFA0B0B"));
        this.tabLayout.setMsgViewWidth(6);
    }

    private void initViewPager() {
        this.viewpager.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundGray));
        this.viewpager.setEnScroll(true);
        this.viewpager.setOffscreenPageLimit(3);
        ArrayList<String> titles = new ArrayList<>();
        titles.add(LocaleController.getString(R.string.fc_page_title_recommend));
        titles.add(LocaleController.getString(R.string.fc_page_title_friends));
        titles.add(LocaleController.getString(R.string.fc_page_title_follow));
        BaseVPAdapter<String> baseVPAdapter = new BaseVPAdapter<String>(getChildFragmentManager(), titles) { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.FriendsCircleFragment.1
            @Override // im.uwrkaxlmjj.ui.adapters.BaseVPAdapter
            public Fragment getIMItem(int position) {
                if (FriendsCircleFragment.this.mFragmentCache == null) {
                    FriendsCircleFragment.this.mFragmentCache = new LruCache(getCount());
                }
                CommFcListFragment newF = (CommFcListFragment) FriendsCircleFragment.this.mFragmentCache.get(Integer.valueOf(position));
                if (newF == null) {
                    if (position == 0) {
                        newF = new FcRecommendFragment();
                    } else if (position == 1) {
                        newF = new FcHomeFragment();
                    } else if (position == 2) {
                        newF = new FcFollowFragment();
                    }
                    if (newF != null) {
                        newF.setFcPageListRefreshListener(FriendsCircleFragment.this.fcPageListRefreshListener);
                    }
                    FriendsCircleFragment.this.mFragmentCache.put(Integer.valueOf(position), newF);
                }
                return newF;
            }
        };
        this.viewPagerAdapter = baseVPAdapter;
        this.viewpager.setAdapter(baseVPAdapter);
        this.viewpager.addOnPageChangeListener(new ViewPager.OnPageChangeListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.FriendsCircleFragment.2
            @Override // androidx.viewpager.widget.ViewPager.OnPageChangeListener
            public void onPageScrolled(int position, float positionOffset, int positionOffsetPixels) {
            }

            @Override // androidx.viewpager.widget.ViewPager.OnPageChangeListener
            public void onPageSelected(int position) {
                FriendsCircleFragment.this.currentSelectedPosition = position;
                if (FriendsCircleFragment.this.listener != null) {
                    FriendsCircleFragment.this.listener.onPageSelected(position);
                }
                if (FriendsCircleFragment.this.tabLayout != null) {
                    FriendsCircleFragment.this.tabLayout.hideMsg(position);
                }
            }

            @Override // androidx.viewpager.widget.ViewPager.OnPageChangeListener
            public void onPageScrollStateChanged(int state) {
            }
        });
        this.tabLayout.setViewPager(this.viewpager);
    }

    public void refreshFcVersionData(FcVersionBean fcVersionBean) {
        SlidingTabLayout slidingTabLayout = this.tabLayout;
        if (slidingTabLayout == null || this.mFragmentCache == null) {
            return;
        }
        this.fcVersionBean = fcVersionBean;
        if (fcVersionBean != null) {
            for (int i = 0; i < this.mFragmentCache.size(); i++) {
                CommFcListFragment commFcListFragment = this.mFragmentCache.get(Integer.valueOf(i));
                if (commFcListFragment != null) {
                    commFcListFragment.setFcVersionBean(fcVersionBean);
                }
            }
            if (fcVersionBean.isFriendState() && this.currentSelectedPosition != 1) {
                this.tabLayout.showDot(1);
                return;
            }
            return;
        }
        slidingTabLayout.hideMsg(0);
        this.tabLayout.hideMsg(1);
        this.tabLayout.hideMsg(2);
        for (int i2 = 0; i2 < this.mFragmentCache.size(); i2++) {
            CommFcListFragment commFcListFragment2 = this.mFragmentCache.get(Integer.valueOf(i2));
            if (commFcListFragment2 != null) {
                commFcListFragment2.setFcVersionBean(new FcVersionBean());
            }
        }
    }

    public void startPublishActivity() {
        String publishJson = AppPreferenceUtil.getString("PublishFcBean", "");
        if (!TextUtils.isEmpty(publishJson)) {
            PublishFcBean publishFcBean = (PublishFcBean) new Gson().fromJson(publishJson, PublishFcBean.class);
            if (publishFcBean != null) {
                presentFragment(new FcPublishActivity(publishFcBean));
                AppPreferenceUtil.putString("PublishFcBean", "");
                return;
            } else {
                openAttachMenu();
                return;
            }
        }
        openAttachMenu();
    }

    private void openAttachMenu() {
        createChatAttachView();
        this.imageSelectorAlert.setCurrentSelectMediaType(0);
        this.imageSelectorAlert.loadGalleryPhotos();
        this.imageSelectorAlert.setMaxSelectedPhotos(9, true);
        this.imageSelectorAlert.init();
        this.imageSelectorAlert.setCancelable(false);
        showDialog(this.imageSelectorAlert);
    }

    private void createChatAttachView() {
        if (this.imageSelectorAlert == null) {
            ImagePreSelectorActivity imagePreSelectorActivity = new ImagePreSelectorActivity(getParentActivity()) { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.FriendsCircleFragment.4
                @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.ImagePreSelectorActivity, im.uwrkaxlmjj.ui.actionbar.BottomSheet
                public void dismissInternal() {
                    if (FriendsCircleFragment.this.imageSelectorAlert.isShowing()) {
                        AndroidUtilities.requestAdjustResize(FriendsCircleFragment.this.getParentActivity(), FriendsCircleFragment.this.classGuid);
                        for (int i = 0; i < FriendsCircleFragment.this.photoEntries.size(); i++) {
                            if (((MediaController.PhotoEntry) FriendsCircleFragment.this.photoEntries.get(i)).isVideo) {
                                super.dismissInternal();
                                return;
                            }
                        }
                    }
                    super.dismissInternal();
                }
            };
            this.imageSelectorAlert = imagePreSelectorActivity;
            imagePreSelectorActivity.setDelegate(new ImagePreSelectorActivity.ChatAttachViewDelegate() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.FriendsCircleFragment.5
                @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.ImagePreSelectorActivity.ChatAttachViewDelegate
                public void didPressedButton(int button, boolean arg, boolean notify, int scheduleDate) {
                    if (button != 8 && button != 7 && (button != 4 || FriendsCircleFragment.this.imageSelectorAlert.getSelectedPhotos().isEmpty())) {
                        if (FriendsCircleFragment.this.imageSelectorAlert != null) {
                            FriendsCircleFragment.this.imageSelectorAlert.dismissWithButtonClick(button);
                            FriendsCircleFragment.this.presentFragment(new FcPublishActivity());
                            return;
                        }
                        return;
                    }
                    if (button != 8) {
                        FriendsCircleFragment.this.imageSelectorAlert.dismiss();
                    }
                    HashMap<Object, Object> selectedPhotos = FriendsCircleFragment.this.imageSelectorAlert.getSelectedPhotos();
                    ArrayList<Object> selectedPhotosOrder = FriendsCircleFragment.this.imageSelectorAlert.getSelectedPhotosOrder();
                    int currentSelectMediaType = FriendsCircleFragment.this.imageSelectorAlert.getCurrentSelectMediaType();
                    if (!selectedPhotos.isEmpty() && !selectedPhotosOrder.isEmpty()) {
                        FriendsCircleFragment friendsCircleFragment = FriendsCircleFragment.this;
                        friendsCircleFragment.presentFragment(new FcPublishActivity(friendsCircleFragment.imageSelectorAlert, selectedPhotos, selectedPhotosOrder, currentSelectMediaType));
                    } else {
                        FriendsCircleFragment.this.presentFragment(new FcPublishActivity());
                    }
                }

                @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.ImagePreSelectorActivity.ChatAttachViewDelegate
                public void didSelectBot(TLRPC.User user) {
                }

                @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.ImagePreSelectorActivity.ChatAttachViewDelegate
                public void onCameraOpened() {
                }

                @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.ImagePreSelectorActivity.ChatAttachViewDelegate
                public View getRevealView() {
                    return null;
                }

                @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.ImagePreSelectorActivity.ChatAttachViewDelegate
                public void needEnterComment() {
                    AndroidUtilities.setAdjustResizeToNothing(FriendsCircleFragment.this.getParentActivity(), FriendsCircleFragment.this.classGuid);
                }
            });
        }
    }
}
