package im.uwrkaxlmjj.ui.hui.friendscircle_v1;

import android.content.Context;
import android.graphics.Color;
import android.graphics.PorterDuff;
import android.graphics.PorterDuffColorFilter;
import android.text.TextUtils;
import android.util.LruCache;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageView;
import androidx.fragment.app.Fragment;
import androidx.viewpager.widget.ViewPager;
import butterknife.BindView;
import com.bjz.comm.net.bean.BResponse;
import com.bjz.comm.net.bean.FcVersionBean;
import com.bjz.comm.net.factory.ApiFactory;
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
import im.uwrkaxlmjj.ui.actionbar.ActionBar;
import im.uwrkaxlmjj.ui.actionbar.ActionBarMenu;
import im.uwrkaxlmjj.ui.actionbar.ActionBarMenuItem;
import im.uwrkaxlmjj.ui.actionbar.BaseFragment;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.adapters.BaseVPAdapter;
import im.uwrkaxlmjj.ui.components.LayoutHelper;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.base.CommFcListFragment;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.base.LazyLoadFragment;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.fcInterface.FcPageListRefreshListener;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.fragments.FcFollowFragment;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.fragments.FcHomeFragment;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.fragments.FcRecommendFragment;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.player.player.VideoPlayerManager;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.FcFollowedManageActivity;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.FcPublishActivity;
import im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.ImagePreSelectorActivity;
import im.uwrkaxlmjj.ui.hviews.NoScrollViewPager;
import io.reactivex.Observable;
import io.reactivex.functions.Consumer;
import java.util.ArrayList;
import java.util.HashMap;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class FriendsCircleActivity extends BaseFragment implements NotificationCenter.NotificationCenterDelegate {

    @BindView(R.attr.containerTab)
    View containerTab;
    private FcVersionBean fcVersionBean;
    private ImagePreSelectorActivity imageSelectorAlert;
    private LruCache<Integer, CommFcListFragment> mFragmentCache;
    private ActionBarMenuItem manageItem;
    private ActionBarMenu menu;
    private Observable<BResponse<FcVersionBean>> observable;
    private ActionBarMenuItem publishItem;

    @BindView(R.attr.tabLayout)
    SlidingTabLayout tabLayout;
    private BaseVPAdapter viewPagerAdapter;

    @BindView(R.attr.viewpager)
    NoScrollViewPager viewpager;
    private int BTN_MANAGE_FOLLOED_USER = 0;
    private int BTN_PUBLISH = 1;
    private int currentSelectedPosition = 0;
    private String TAG = FriendsCircleActivity.class.getSimpleName();
    private FcPageListRefreshListener fcPageListRefreshListener = new FcPageListRefreshListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.FriendsCircleActivity.6
        @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.fcInterface.FcPageListRefreshListener
        public void onRefreshed(int pageIndex) {
            if (FriendsCircleActivity.this.tabLayout != null && pageIndex < FriendsCircleActivity.this.mFragmentCache.size()) {
                FriendsCircleActivity.this.tabLayout.hideMsg(pageIndex);
                if (FriendsCircleActivity.this.fcVersionBean != null) {
                    if (pageIndex == 0) {
                        FriendsCircleActivity.this.fcVersionBean.setRecommendState(false);
                    } else if (pageIndex == 1) {
                        FriendsCircleActivity.this.fcVersionBean.setFriendState(false);
                    } else if (pageIndex == 2) {
                        FriendsCircleActivity.this.fcVersionBean.setFollowState(false);
                    }
                    if (!FriendsCircleActivity.this.fcVersionBean.isFriendState()) {
                        NotificationCenter.getInstance(FriendsCircleActivity.this.currentAccount).postNotificationName(NotificationCenter.userFriendsCircleUpdate, new Object[0]);
                    }
                }
            }
        }

        @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.fcInterface.FcPageListRefreshListener
        public void startFcPublishActivity() {
            FriendsCircleActivity.this.startPublishActivity();
        }
    };
    private ArrayList<MediaController.PhotoEntry> photoEntries = new ArrayList<>();

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public View createView(Context context) {
        this.fragmentView = LayoutInflater.from(context).inflate(R.layout.activity_friends_ciecle, (ViewGroup) null, false);
        this.fragmentView.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundGray));
        VideoPlayerManager.getInstance().setVolume(0);
        useButterKnife();
        initActionBar();
        initTabLayout();
        initViewPager();
        return this.fragmentView;
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public boolean onFragmentCreate() {
        NotificationCenter.getInstance(this.currentAccount).addObserver(this, NotificationCenter.userFriendsCircleUpdate);
        return super.onFragmentCreate();
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onResume() {
        super.onResume();
        queryFcVersion();
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

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onPause() {
        super.onPause();
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

    @Override // im.uwrkaxlmjj.messenger.NotificationCenter.NotificationCenterDelegate
    public void didReceivedNotification(int id, int account, Object... args) {
        CommFcListFragment commFcListFragment;
        if (id == NotificationCenter.userFriendsCircleUpdate && this.tabLayout != null && this.mFragmentCache != null && args.length != 0 && (args[0] instanceof TLRPC.TL_updateUserMomentStateV1)) {
            TLRPC.TL_updateUserMomentStateV1 userMomentStateV1 = (TLRPC.TL_updateUserMomentStateV1) args[0];
            if (userMomentStateV1.type == 2 && userMomentStateV1.user_id != 0) {
                if (this.mFragmentCache.size() > 1 && (commFcListFragment = this.mFragmentCache.get(1)) != null) {
                    FcVersionBean fcVersionBean = commFcListFragment.getFcVersionBean();
                    fcVersionBean.setFriendState(true);
                    commFcListFragment.setFcVersionBean(fcVersionBean);
                }
                this.tabLayout.showDot(1);
                return;
            }
            this.tabLayout.hideMsg(1);
        }
    }

    private void queryFcVersion() {
        this.observable = ApiFactory.getInstance().getApiMomentForum().checkVersion();
        RxHelper.getInstance().sendRequest(this.TAG, this.observable, new Consumer<BResponse<FcVersionBean>>() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.FriendsCircleActivity.1
            @Override // io.reactivex.functions.Consumer
            public void accept(BResponse<FcVersionBean> response) throws Exception {
                FriendsCircleActivity.this.refreshFcVersionData(response.Data);
            }
        }, new Consumer<Throwable>() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.FriendsCircleActivity.2
            @Override // io.reactivex.functions.Consumer
            public void accept(Throwable throwable) throws Exception {
            }
        });
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onFragmentDestroy() {
        super.onFragmentDestroy();
        NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.userFriendsCircleUpdate);
        getConnectionsManager().cancelRequestsForGuid(this.classGuid);
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

    private void initActionBar() {
        this.actionBar = createActionBar(getParentActivity());
        this.actionBar.setCastShadows(false);
        this.actionBar.setBackButtonImage(R.id.ic_back);
        this.actionBar.setActionBarMenuOnItemClick(new ActionBar.ActionBarMenuOnItemClick() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.FriendsCircleActivity.3
            @Override // im.uwrkaxlmjj.ui.actionbar.ActionBar.ActionBarMenuOnItemClick
            public void onItemClick(int id) {
                if (id != -1) {
                    if (id != FriendsCircleActivity.this.BTN_PUBLISH || (FriendsCircleActivity.this.currentSelectedPosition != 0 && FriendsCircleActivity.this.currentSelectedPosition != 1)) {
                        if (id == FriendsCircleActivity.this.BTN_MANAGE_FOLLOED_USER && FriendsCircleActivity.this.currentSelectedPosition == 2) {
                            FriendsCircleActivity.this.presentFragment(new FcFollowedManageActivity());
                            return;
                        }
                        return;
                    }
                    FriendsCircleActivity.this.startPublishActivity();
                    return;
                }
                FriendsCircleActivity.this.finishFragment();
            }
        });
        ActionBarMenu actionBarMenuCreateMenu = this.actionBar.createMenu();
        this.menu = actionBarMenuCreateMenu;
        ActionBarMenuItem actionBarMenuItemAddItemWithWidth = actionBarMenuCreateMenu.addItemWithWidth(this.BTN_MANAGE_FOLLOED_USER, R.id.ic_fc_menu_manage_followed_user, AndroidUtilities.dp(40.0f), 0, 14);
        this.manageItem = actionBarMenuItemAddItemWithWidth;
        ((ImageView) actionBarMenuItemAddItemWithWidth.getContentView()).setColorFilter(new PorterDuffColorFilter(Theme.getColor(Theme.key_actionBarDefaultIcon), PorterDuff.Mode.SRC_IN));
        ActionBarMenuItem actionBarMenuItemAddItemWithWidth2 = this.menu.addItemWithWidth(this.BTN_PUBLISH, R.id.ic_fc_publish_blue, AndroidUtilities.dp(40.0f), 0, 14);
        this.publishItem = actionBarMenuItemAddItemWithWidth2;
        ImageView contentView = (ImageView) actionBarMenuItemAddItemWithWidth2.getContentView();
        contentView.clearColorFilter();
        this.manageItem.setVisibility(8);
    }

    private void initTabLayout() {
        ((ViewGroup) this.fragmentView).removeView(this.containerTab);
        this.tabLayout.setMsgViewBackgroundColor(Color.parseColor("#FFFA0B0B"));
        this.tabLayout.setMsgViewWidth(6);
        if (!Theme.getCurrentTheme().isLight()) {
            this.tabLayout.setTextSelectColor(Theme.getColor(Theme.key_windowBackgroundWhiteBlackText));
            this.tabLayout.setTextUnselectColor(Theme.getColor(Theme.key_windowBackgroundWhiteGrayText6));
        }
        this.actionBar.addView(this.containerTab, LayoutHelper.createFrame(-1.0f, -2.0f, 81, 68.0f, 0.0f, 68.0f, 0.0f));
        View view = new View(getParentActivity());
        view.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundGray));
        this.actionBar.addView(view, LayoutHelper.createFrame(-1.0f, 0.5f, 80));
    }

    private void initViewPager() {
        this.viewpager.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundGray));
        this.viewpager.setEnScroll(true);
        this.viewpager.setOffscreenPageLimit(3);
        ArrayList<String> titles = new ArrayList<>();
        titles.add(LocaleController.getString(R.string.fc_page_title_recommend));
        titles.add(LocaleController.getString(R.string.fc_page_title_friends));
        titles.add(LocaleController.getString(R.string.fc_page_title_follow));
        BaseVPAdapter<String> baseVPAdapter = new BaseVPAdapter<String>(getParentActivity().getSupportFragmentManager(), titles) { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.FriendsCircleActivity.4
            @Override // im.uwrkaxlmjj.ui.adapters.BaseVPAdapter
            public Fragment getIMItem(int position) {
                if (FriendsCircleActivity.this.mFragmentCache == null) {
                    FriendsCircleActivity.this.mFragmentCache = new LruCache(getCount());
                }
                CommFcListFragment newF = (CommFcListFragment) FriendsCircleActivity.this.mFragmentCache.get(Integer.valueOf(position));
                if (newF == null) {
                    if (position == 0) {
                        newF = new FcRecommendFragment();
                    } else if (position == 1) {
                        newF = new FcHomeFragment();
                    } else if (position == 2) {
                        newF = new FcFollowFragment();
                    }
                    if (newF != null) {
                        newF.setFcPageListRefreshListener(FriendsCircleActivity.this.fcPageListRefreshListener);
                    }
                    FriendsCircleActivity.this.mFragmentCache.put(Integer.valueOf(position), newF);
                }
                return newF;
            }
        };
        this.viewPagerAdapter = baseVPAdapter;
        this.viewpager.setAdapter(baseVPAdapter);
        this.viewpager.addOnPageChangeListener(new ViewPager.OnPageChangeListener() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.FriendsCircleActivity.5
            @Override // androidx.viewpager.widget.ViewPager.OnPageChangeListener
            public void onPageScrolled(int position, float positionOffset, int positionOffsetPixels) {
            }

            @Override // androidx.viewpager.widget.ViewPager.OnPageChangeListener
            public void onPageSelected(int position) {
                FriendsCircleActivity.this.currentSelectedPosition = position;
                if (FriendsCircleActivity.this.menu != null) {
                    if (position == 2) {
                        FriendsCircleActivity.this.manageItem.setVisibility(0);
                        FriendsCircleActivity.this.publishItem.setVisibility(8);
                    } else {
                        FriendsCircleActivity.this.manageItem.setVisibility(8);
                        FriendsCircleActivity.this.publishItem.setVisibility(0);
                    }
                }
                if (FriendsCircleActivity.this.tabLayout != null) {
                    FriendsCircleActivity.this.tabLayout.hideMsg(position);
                }
            }

            @Override // androidx.viewpager.widget.ViewPager.OnPageChangeListener
            public void onPageScrollStateChanged(int state) {
            }
        });
        this.tabLayout.setViewPager(this.viewpager);
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public boolean canBeginSlide() {
        NoScrollViewPager noScrollViewPager = this.viewpager;
        return noScrollViewPager != null && noScrollViewPager.getCurrentItem() == 0;
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
            if (fcVersionBean.isFriendState()) {
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
            ImagePreSelectorActivity imagePreSelectorActivity = new ImagePreSelectorActivity(getParentActivity()) { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.FriendsCircleActivity.7
                @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.ImagePreSelectorActivity, im.uwrkaxlmjj.ui.actionbar.BottomSheet
                public void dismissInternal() {
                    if (FriendsCircleActivity.this.imageSelectorAlert.isShowing()) {
                        AndroidUtilities.requestAdjustResize(FriendsCircleActivity.this.getParentActivity(), FriendsCircleActivity.this.classGuid);
                        for (int i = 0; i < FriendsCircleActivity.this.photoEntries.size(); i++) {
                            if (((MediaController.PhotoEntry) FriendsCircleActivity.this.photoEntries.get(i)).isVideo) {
                                super.dismissInternal();
                                return;
                            }
                        }
                    }
                    super.dismissInternal();
                }
            };
            this.imageSelectorAlert = imagePreSelectorActivity;
            imagePreSelectorActivity.setDelegate(new ImagePreSelectorActivity.ChatAttachViewDelegate() { // from class: im.uwrkaxlmjj.ui.hui.friendscircle_v1.FriendsCircleActivity.8
                @Override // im.uwrkaxlmjj.ui.hui.friendscircle_v1.ui.ImagePreSelectorActivity.ChatAttachViewDelegate
                public void didPressedButton(int button, boolean arg, boolean notify, int scheduleDate) {
                    if (button != 8 && button != 7 && (button != 4 || FriendsCircleActivity.this.imageSelectorAlert.getSelectedPhotos().isEmpty())) {
                        if (FriendsCircleActivity.this.imageSelectorAlert != null) {
                            FriendsCircleActivity.this.imageSelectorAlert.dismissWithButtonClick(button);
                            FriendsCircleActivity.this.presentFragment(new FcPublishActivity());
                            return;
                        }
                        return;
                    }
                    if (button != 8) {
                        FriendsCircleActivity.this.imageSelectorAlert.dismiss();
                    }
                    HashMap<Object, Object> selectedPhotos = FriendsCircleActivity.this.imageSelectorAlert.getSelectedPhotos();
                    ArrayList<Object> selectedPhotosOrder = FriendsCircleActivity.this.imageSelectorAlert.getSelectedPhotosOrder();
                    int currentSelectMediaType = FriendsCircleActivity.this.imageSelectorAlert.getCurrentSelectMediaType();
                    if (!selectedPhotos.isEmpty() && !selectedPhotosOrder.isEmpty()) {
                        FriendsCircleActivity friendsCircleActivity = FriendsCircleActivity.this;
                        friendsCircleActivity.presentFragment(new FcPublishActivity(friendsCircleActivity.imageSelectorAlert, selectedPhotos, selectedPhotosOrder, currentSelectMediaType));
                    } else {
                        FriendsCircleActivity.this.presentFragment(new FcPublishActivity());
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
                    AndroidUtilities.setAdjustResizeToNothing(FriendsCircleActivity.this.getParentActivity(), FriendsCircleActivity.this.classGuid);
                }
            });
        }
    }
}
