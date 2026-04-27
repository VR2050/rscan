package im.uwrkaxlmjj.ui;

import android.animation.Animator;
import android.animation.AnimatorListenerAdapter;
import android.animation.AnimatorSet;
import android.animation.ObjectAnimator;
import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.os.Build;
import android.os.Bundle;
import android.text.SpannableString;
import android.text.TextUtils;
import android.text.style.ForegroundColorSpan;
import android.util.Log;
import android.util.LruCache;
import android.util.Property;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.LinearLayout;
import android.widget.TextView;
import androidx.core.app.NotificationCompat;
import androidx.core.content.ContextCompat;
import androidx.fragment.app.Fragment;
import androidx.fragment.app.FragmentManager;
import com.bjz.comm.net.utils.HttpUtils;
import com.bjz.comm.net.utils.RxHelper;
import com.bjz.comm.net.utils.TokenLoader;
import com.google.android.exoplayer2.C;
import com.google.android.exoplayer2.DefaultRenderersFactory;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.BuildVars;
import im.uwrkaxlmjj.messenger.FileLog;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.messenger.MessagesController;
import im.uwrkaxlmjj.messenger.NotificationCenter;
import im.uwrkaxlmjj.messenger.UserObject;
import im.uwrkaxlmjj.messenger.utils.status.StatusBarUtils;
import im.uwrkaxlmjj.messenger.voip.VoIPActionsReceiver;
import im.uwrkaxlmjj.tgnet.ConnectionsManager;
import im.uwrkaxlmjj.tgnet.FCTokenRequestCallback;
import im.uwrkaxlmjj.tgnet.ParamsUtil;
import im.uwrkaxlmjj.tgnet.RequestDelegate;
import im.uwrkaxlmjj.tgnet.TLObject;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.tgnet.TLRPC2;
import im.uwrkaxlmjj.tgnet.TLRPCContacts;
import im.uwrkaxlmjj.tgnet.TLRPCLogin;
import im.uwrkaxlmjj.ui.actionbar.BaseFragment;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.adapters.BaseVPAdapter;
import im.uwrkaxlmjj.ui.bottom.BottomBarItem;
import im.uwrkaxlmjj.ui.bottom.BottomBarLayout;
import im.uwrkaxlmjj.ui.fragments.BaseFmts;
import im.uwrkaxlmjj.ui.fragments.ContactsFragment;
import im.uwrkaxlmjj.ui.fragments.DialogsFragment;
import im.uwrkaxlmjj.ui.fragments.DiscoveryFragment;
import im.uwrkaxlmjj.ui.fragments.MeFragmentV2;
import im.uwrkaxlmjj.ui.fragments.TabWebFragment;
import im.uwrkaxlmjj.ui.fragments.onRefreshMainInterface;
import im.uwrkaxlmjj.ui.hui.login.ChangePersonalInformationActivity;
import im.uwrkaxlmjj.ui.hui.wallet_public.utils.WalletErrorUtil;
import im.uwrkaxlmjj.ui.hviews.NoScrollViewPager;
import im.uwrkaxlmjj.ui.utils.AppUpdater;
import im.uwrkaxlmjj.utils.FingerprintUtil;
import java.util.ArrayList;
import java.util.Timer;
import java.util.TimerTask;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class IndexActivity extends BaseFragment implements NotificationCenter.NotificationCenterDelegate, DiscoveryFragment.Delegate, onRefreshMainInterface {
    private static final String TAG = IndexActivity.class.getSimpleName();
    private BaseVPAdapter adapter;
    private int currentUnreadCount;
    private int dialogsType;
    private TLRPC2.TL_DiscoveryPageSetting discoveryData;
    private LruCache<Integer, BaseFmts> fragmentsCache;
    private LinearLayout llDialogMenuLayout;
    private BottomBarLayout mBottomBarLayout;
    private boolean mIsGettingFullUserInfo;
    private boolean mUserInfoIsCompleted;
    private NoScrollViewPager mVpContent;
    private boolean needShowDisTab;
    private int reqDisToken;
    private TimerTask syncRemoteContactsTask;
    private Timer syncRemoteContactsTimer;
    private boolean timerInit;
    private TextView tvArchiveText;
    private TextView tvCanReadText;
    private TextView tvDeleteText;

    private void startTimer() {
        if (this.timerInit) {
            return;
        }
        if (this.syncRemoteContactsTimer == null) {
            this.syncRemoteContactsTimer = new Timer();
        }
        if (this.syncRemoteContactsTask == null) {
            this.syncRemoteContactsTask = new TimerTask() { // from class: im.uwrkaxlmjj.ui.IndexActivity.1
                @Override // java.util.TimerTask, java.lang.Runnable
                public void run() {
                    IndexActivity.this.getMessagesController().getContactsApplyDifferenceV2(true, false);
                }
            };
        }
        this.syncRemoteContactsTimer.schedule(this.syncRemoteContactsTask, DefaultRenderersFactory.DEFAULT_ALLOWED_VIDEO_JOINING_TIME_MS, 30000L);
        this.timerInit = true;
    }

    private void stopTimer() {
        Timer timer = this.syncRemoteContactsTimer;
        if (timer != null) {
            timer.cancel();
            this.syncRemoteContactsTimer = null;
        }
        TimerTask timerTask = this.syncRemoteContactsTask;
        if (timerTask != null) {
            timerTask.cancel();
            this.syncRemoteContactsTask = null;
        }
        this.timerInit = false;
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    protected void onBecomeFullyVisible() {
        super.onBecomeFullyVisible();
        if (!AppUpdater.hasChecked && (getParentActivity() instanceof LaunchActivity)) {
            ((LaunchActivity) getParentActivity()).checkAppUpdate(false);
        }
    }

    public IndexActivity() {
        this.adapter = null;
        this.syncRemoteContactsTimer = null;
        this.syncRemoteContactsTask = null;
        this.timerInit = false;
    }

    public IndexActivity(Bundle args) {
        super(args);
        this.adapter = null;
        this.syncRemoteContactsTimer = null;
        this.syncRemoteContactsTask = null;
        this.timerInit = false;
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public boolean onFragmentCreate() {
        super.onFragmentCreate();
        this.dialogsType = MessagesController.getMainSettings(this.currentAccount).getInt("dialogsType", 0);
        NotificationCenter.getGlobalInstance().addObserver(this, NotificationCenter.didSetPasscode);
        NotificationCenter.getInstance(this.currentAccount).addObserver(this, NotificationCenter.contactApplyUpdateCount);
        NotificationCenter.getInstance(this.currentAccount).addObserver(this, NotificationCenter.userFriendsCircleUpdate);
        NotificationCenter.getInstance(this.currentAccount).addObserver(this, NotificationCenter.userFullInfoDidLoad);
        getNotificationCenter().addObserver(this, NotificationCenter.appDidLogout);
        HttpUtils.getInstance().clearCache();
        TokenLoader.getInstance().setCallBack(FCTokenRequestCallback.getInstance());
        getConnectionsManager().updateDcSettings();
        setNavigationBarColor(Theme.getColor(Theme.key_bottomBarBackground));
        return true;
    }

    public void rebuidView() {
        BaseVPAdapter baseVPAdapter = this.adapter;
        if (baseVPAdapter != null) {
            baseVPAdapter.notifyDataSetChanged();
        }
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public View createView(Context context) {
        this.actionBar.setAddToContainer(false);
        this.fragmentView = LayoutInflater.from(context).inflate(R.layout.activity_index, (ViewGroup) null, false);
        this.mVpContent = (NoScrollViewPager) this.fragmentView.findViewById(R.attr.vp_content);
        this.mBottomBarLayout = (BottomBarLayout) this.fragmentView.findViewById(R.attr.btm_layout);
        LinearLayout linearLayout = (LinearLayout) this.fragmentView.findViewById(R.attr.llDialogMenuLayout);
        this.llDialogMenuLayout = linearLayout;
        linearLayout.setBackgroundColor(Theme.getColor(Theme.key_bottomBarBackground));
        this.tvCanReadText = (TextView) this.fragmentView.findViewById(R.attr.tvCanReadText);
        this.tvDeleteText = (TextView) this.fragmentView.findViewById(R.attr.tvDeleteText);
        this.tvArchiveText = (TextView) this.fragmentView.findViewById(R.attr.tvArchiveText);
        this.tvCanReadText.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteBlueText));
        this.tvCanReadText.setBackground(Theme.getSelectorDrawable(false));
        this.tvCanReadText.setText(LocaleController.getString(R.string.MarkAllAsRead));
        this.tvDeleteText.setText(LocaleController.getString("Delete", R.string.Delete));
        this.tvDeleteText.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteRedText));
        this.tvDeleteText.setBackground(Theme.getSelectorDrawable(false));
        this.tvArchiveText.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteBlackText));
        this.tvArchiveText.setBackground(Theme.getSelectorDrawable(false));
        this.tvArchiveText.setVisibility(8);
        this.tvCanReadText.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$IndexActivity$-b4E6RSTFgbiW9XUfbpqiDvQ5KQ
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                this.f$0.lambda$createView$0$IndexActivity(view);
            }
        });
        this.tvDeleteText.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$IndexActivity$bq7jgQfutRr8OrJey6-NCj_i6Qs
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                this.f$0.lambda$createView$1$IndexActivity(view);
            }
        });
        this.mBottomBarLayout.setBackgroundColor(Theme.getColor(Theme.key_bottomBarBackground));
        this.mBottomBarLayout.setOnItemSelectedListener(new BottomBarLayout.OnItemSelectedListener() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$IndexActivity$velVzlArhHv-90YgfffhfGqvx1M
            @Override // im.uwrkaxlmjj.ui.bottom.BottomBarLayout.OnItemSelectedListener
            public final void onItemSelected(BottomBarItem bottomBarItem, int i, int i2) {
                this.f$0.lambda$createView$2$IndexActivity(bottomBarItem, i, i2);
            }
        });
        SharedPreferences sharedPreferences = MessagesController.getMainSettings(this.currentAccount);
        int value = sharedPreferences.getInt("contacts_apply_count", 0);
        BottomBarLayout bottomBarLayout = this.mBottomBarLayout;
        if (bottomBarLayout != null) {
            bottomBarLayout.setUnread(1, value);
        }
        if (Theme.getCurrentTheme().name.toLowerCase().contains("dark")) {
            StatusBarUtils.setStatusBarDarkTheme(getParentActivity(), false);
        } else {
            StatusBarUtils.setStatusBarDarkTheme(getParentActivity(), true);
        }
        initFragments();
        getDiscoveryData();
        doChannelBind();
        return this.fragmentView;
    }

    public /* synthetic */ void lambda$createView$0$IndexActivity(View v) {
        BaseFmts f = getChildFragment(0);
        if (f instanceof DialogsFragment) {
            ((DialogsFragment) f).perfromSelectedDialogsAction(4);
        }
    }

    public /* synthetic */ void lambda$createView$1$IndexActivity(View v) {
        BaseFmts f = getChildFragment(0);
        if (f instanceof DialogsFragment) {
            ((DialogsFragment) f).showDeleteOrClearSheet();
        }
    }

    public /* synthetic */ void lambda$createView$2$IndexActivity(BottomBarItem bottomBarItem, int previousPosition, int currentPosition) {
        if (previousPosition == 0) {
            BaseFmts f = getChildFragment(0);
            if (f instanceof DialogsFragment) {
                ((DialogsFragment) f).closeSearchView(previousPosition == currentPosition);
                return;
            }
            return;
        }
        if (previousPosition == 1) {
            BaseFmts f2 = getChildFragment(1);
            if (f2 instanceof ContactsFragment) {
                ((ContactsFragment) f2).closeSearchView(previousPosition == currentPosition);
            }
        }
    }

    private void doChannelBind() {
        SharedPreferences sharedPreferences = MessagesController.getMainSettings(this.currentAccount);
        boolean needChannelBind = sharedPreferences.getBoolean("need_channel_bind", true);
        if (!needChannelBind) {
            return;
        }
        bind(null, null);
    }

    private void bind(String channel, String custom) {
        if (TextUtils.isEmpty(channel) && TextUtils.isEmpty(custom)) {
            return;
        }
        TLRPCLogin.TL_auth_signUpBind req = new TLRPCLogin.TL_auth_signUpBind();
        req.company = "Sbcc";
        req.device = FingerprintUtil.getDeviceId(getParentActivity());
        req.userId = getUserConfig().clientUserId;
        TLRPC.TL_dataJSON dataJSON = new TLRPC.TL_dataJSON();
        dataJSON.data = ParamsUtil.toJson(new String[]{"op_channel", "op_data"}, channel, custom);
        req.extend = dataJSON;
        getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$IndexActivity$_RFyvYsW43KzNp1pp_HuoSJrBUg
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                this.f$0.lambda$bind$3$IndexActivity(tLObject, tL_error);
            }
        });
    }

    public /* synthetic */ void lambda$bind$3$IndexActivity(TLObject response, TLRPC.TL_error error) {
        if (error != null) {
            FileLog.e("bind channel failed, error:" + error.text);
            return;
        }
        if (response instanceof TLRPC.TL_boolTrue) {
            FileLog.d("bind channel success");
            SharedPreferences sharedPreferences = MessagesController.getMainSettings(this.currentAccount);
            sharedPreferences.edit().putBoolean("need_channel_bind", false).commit();
            return;
        }
        FileLog.d("bind channel failed");
    }

    private void initFragments() {
        this.mVpContent.setOffscreenPageLimit(4);
        this.fragmentsCache = new LruCache<>(5);
        AnonymousClass3 anonymousClass3 = new AnonymousClass3(getParentActivity().getSupportFragmentManager(), new Object[0]);
        this.adapter = anonymousClass3;
        this.mVpContent.setAdapter(anonymousClass3);
        this.mBottomBarLayout.setViewPager(this.mVpContent);
    }

    /* JADX INFO: renamed from: im.uwrkaxlmjj.ui.IndexActivity$3, reason: invalid class name */
    class AnonymousClass3 extends BaseVPAdapter {
        AnonymousClass3(FragmentManager fm, Object... mData) {
            super(fm, mData);
        }

        @Override // androidx.viewpager.widget.PagerAdapter
        public void notifyDataSetChanged() {
            if (IndexActivity.this.fragmentsCache != null) {
                IndexActivity.this.fragmentsCache.evictAll();
            }
            super.notifyDataSetChanged();
        }

        @Override // im.uwrkaxlmjj.ui.adapters.BaseVPAdapter
        public Fragment getIMItem(int position) {
            BaseFmts fragment = (BaseFmts) IndexActivity.this.fragmentsCache.get(Integer.valueOf(position));
            if (fragment == null) {
                if (position == 0) {
                    fragment = new DialogsFragment(IndexActivity.this);
                    ((DialogsFragment) fragment).setDilogsType(IndexActivity.this.dialogsType);
                    ((DialogsFragment) fragment).setDelegate(new DialogsFragment.FmtConsumDelegate() { // from class: im.uwrkaxlmjj.ui.IndexActivity.3.1
                        @Override // im.uwrkaxlmjj.ui.fragments.DialogsFragment.FmtConsumDelegate
                        public void changeUnreadCount(int count) {
                            if (IndexActivity.this.mBottomBarLayout != null) {
                                IndexActivity.this.mBottomBarLayout.setUnread(0, count);
                            }
                        }

                        @Override // im.uwrkaxlmjj.ui.fragments.DialogsFragment.FmtConsumDelegate
                        public void onEditModelChange(final boolean isEdit, boolean hasCanReadCount) {
                            if (IndexActivity.this.llDialogMenuLayout != null && IndexActivity.this.mBottomBarLayout != null) {
                                if (isEdit) {
                                    IndexActivity.this.tvCanReadText.setText(LocaleController.getString(R.string.MarkAllAsRead));
                                    if (hasCanReadCount) {
                                        IndexActivity.this.tvCanReadText.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteBlueText));
                                        IndexActivity.this.tvCanReadText.setEnabled(true);
                                    } else {
                                        IndexActivity.this.tvCanReadText.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteBlackText));
                                        IndexActivity.this.tvCanReadText.setEnabled(false);
                                    }
                                }
                                IndexActivity.this.mBottomBarLayout.clearAnimation();
                                IndexActivity.this.llDialogMenuLayout.clearAnimation();
                                int pivotY = IndexActivity.this.mBottomBarLayout.getMeasuredHeight() / 2;
                                IndexActivity.this.mBottomBarLayout.setPivotY(pivotY);
                                IndexActivity.this.llDialogMenuLayout.setPivotY(pivotY);
                                Animator.AnimatorListener listener = new AnimatorListenerAdapter() { // from class: im.uwrkaxlmjj.ui.IndexActivity.3.1.1
                                    @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                                    public void onAnimationStart(Animator animation) {
                                        if (isEdit) {
                                            IndexActivity.this.llDialogMenuLayout.setVisibility(0);
                                        } else {
                                            IndexActivity.this.mBottomBarLayout.setVisibility(0);
                                        }
                                    }

                                    @Override // android.animation.AnimatorListenerAdapter, android.animation.Animator.AnimatorListener
                                    public void onAnimationEnd(Animator animation) {
                                        if (!isEdit) {
                                            IndexActivity.this.mBottomBarLayout.setVisibility(0);
                                            IndexActivity.this.llDialogMenuLayout.setVisibility(8);
                                        } else {
                                            IndexActivity.this.llDialogMenuLayout.setVisibility(0);
                                            IndexActivity.this.mBottomBarLayout.setVisibility(8);
                                        }
                                    }
                                };
                                AnimatorSet animatorSet = new AnimatorSet();
                                ArrayList<Animator> animators = new ArrayList<>();
                                BottomBarLayout bottomBarLayout = IndexActivity.this.mBottomBarLayout;
                                Property property = View.SCALE_Y;
                                float[] fArr = new float[2];
                                fArr[0] = isEdit ? 1.0f : 0.1f;
                                fArr[1] = isEdit ? 0.1f : 1.0f;
                                Animator animator1 = ObjectAnimator.ofFloat(bottomBarLayout, (Property<BottomBarLayout, Float>) property, fArr);
                                animator1.addListener(listener);
                                animators.add(animator1);
                                LinearLayout linearLayout = IndexActivity.this.llDialogMenuLayout;
                                Property property2 = View.SCALE_Y;
                                float[] fArr2 = new float[2];
                                fArr2[0] = isEdit ? 0.1f : 1.0f;
                                fArr2[1] = isEdit ? 1.0f : 0.1f;
                                Animator animator2 = ObjectAnimator.ofFloat(linearLayout, (Property<LinearLayout, Float>) property2, fArr2);
                                animator2.addListener(listener);
                                animators.add(animator2);
                                animatorSet.playTogether(animators);
                                animatorSet.setDuration(250L);
                                animatorSet.start();
                            }
                        }

                        @Override // im.uwrkaxlmjj.ui.fragments.DialogsFragment.FmtConsumDelegate
                        public void onUpdateState(boolean hasCanReadCount, int selectDialogsCount, int canReadCount) {
                            if (selectDialogsCount > 0 && canReadCount > 0) {
                                IndexActivity.this.tvCanReadText.setEnabled(true);
                                IndexActivity.this.tvCanReadText.setText(LocaleController.getString(R.string.MarkAsRead));
                                IndexActivity.this.tvCanReadText.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteBlueText));
                            } else if (selectDialogsCount > 0 && canReadCount <= 0) {
                                IndexActivity.this.tvCanReadText.setEnabled(true);
                                IndexActivity.this.tvCanReadText.setText(LocaleController.getString(R.string.MarkAsRead));
                                IndexActivity.this.tvCanReadText.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteBlackText));
                            } else if (hasCanReadCount) {
                                IndexActivity.this.tvCanReadText.setEnabled(true);
                                IndexActivity.this.tvCanReadText.setText(LocaleController.getString(R.string.MarkAllAsRead));
                                IndexActivity.this.tvCanReadText.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteBlueText));
                            } else {
                                IndexActivity.this.tvCanReadText.setEnabled(false);
                                IndexActivity.this.tvCanReadText.setText(LocaleController.getString(R.string.MarkAllAsRead));
                                IndexActivity.this.tvCanReadText.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteBlackText));
                            }
                            if (selectDialogsCount > 0) {
                                IndexActivity.this.tvDeleteText.setEnabled(true);
                                IndexActivity.this.tvDeleteText.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteRedText3));
                            } else {
                                IndexActivity.this.tvDeleteText.setEnabled(false);
                                IndexActivity.this.tvDeleteText.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteBlackText));
                            }
                        }
                    });
                }
                if (position == 1) {
                    fragment = new ContactsFragment();
                }
                if (position == 2) {
                    if (IndexActivity.this.needShowDisTab) {
                        fragment = new TabWebFragment();
                        ((TabWebFragment) fragment).setDelegate(IndexActivity.this);
                    } else {
                        fragment = new DiscoveryFragment(IndexActivity.this);
                        ((DiscoveryFragment) fragment).setDelegate(IndexActivity.this);
                    }
                } else if (position == 3) {
                    if (IndexActivity.this.needShowDisTab) {
                        fragment = new DiscoveryFragment(IndexActivity.this);
                        ((DiscoveryFragment) fragment).setDelegate(IndexActivity.this);
                    } else {
                        fragment = new MeFragmentV2();
                    }
                } else if (IndexActivity.this.needShowDisTab && position == 4) {
                    fragment = new MeFragmentV2();
                }
                IndexActivity.this.fragmentsCache.put(Integer.valueOf(position), fragment);
            }
            return fragment;
        }

        @Override // im.uwrkaxlmjj.ui.adapters.BaseVPAdapter, androidx.viewpager.widget.PagerAdapter
        public int getCount() {
            return IndexActivity.this.needShowDisTab ? 5 : 4;
        }
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onResume() {
        super.onResume();
        Log.d("bond", "onResume");
        getFcUnRead();
        if (!BuildVars.DEBUG_VERSION) {
            getFcUrlFromServer();
        }
        callBackFragmentsLifeCycle(true);
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onPause() {
        super.onPause();
        stopTimer();
        callBackFragmentsLifeCycle(false);
    }

    private void updateBottomItem() {
        BottomBarLayout bottomBarLayout = this.mBottomBarLayout;
        if (bottomBarLayout == null) {
            return;
        }
        if (this.needShowDisTab) {
            if (bottomBarLayout.getChildCount() == 4) {
                BottomBarItem.Builder builder = new BottomBarItem.Builder(getParentActivity());
                builder.normalIcon(ContextCompat.getDrawable(getParentActivity(), R.drawable.ic_btm_web_normal));
                this.mBottomBarLayout.addItem(builder.create(this.discoveryData.getS().get(0).getLogo(), R.drawable.ic_btm_web_normal, R.drawable.ic_btm_web_normal, this.discoveryData.getS().get(0).getTitle()), 2);
                return;
            }
            return;
        }
        if (bottomBarLayout.getChildCount() == 5) {
            this.mBottomBarLayout.removeItem(2);
        }
    }

    private void showIncomingNotification(String title, String name, String subText, TLRPC.User user, boolean onlyone) {
        Intent intent = new Intent(getParentActivity(), (Class<?>) LaunchActivity.class);
        intent.setAction("im.uwrkaxlmjj.contacts.add");
        intent.addFlags(805306368);
        Notification.Builder builder = new Notification.Builder(getParentActivity()).setContentTitle(title).setContentText(name).setSubText(subText).setAutoCancel(true).setWhen(System.currentTimeMillis()).setSmallIcon(R.id.ic_launcher).setContentIntent(PendingIntent.getActivity(getParentActivity(), 0, intent, 0));
        if (Build.VERSION.SDK_INT >= 17) {
            builder.setShowWhen(true);
        }
        if (Build.VERSION.SDK_INT >= 26) {
            NotificationManager nm = (NotificationManager) getParentActivity().getSystemService("notification");
            NotificationChannel oldChannel = nm.getNotificationChannel("10111213");
            boolean needCreate = true;
            if (oldChannel != null) {
                needCreate = false;
            }
            if (needCreate) {
                NotificationChannel chan = new NotificationChannel("10111213", "好友请求", 3);
                chan.enableVibration(false);
                chan.enableLights(false);
                nm.createNotificationChannel(chan);
            }
            builder.setChannelId("10111213");
        }
        if (!onlyone) {
            Intent endIntent = new Intent(getParentActivity(), (Class<?>) VoIPActionsReceiver.class);
            endIntent.setAction(getParentActivity().getPackageName() + ".CANCEL_CONTACT_APPLY");
            endIntent.putExtra("call_id", 111);
            CharSequence endTitle = LocaleController.getString("Cancel", R.string.Cancel);
            if (Build.VERSION.SDK_INT >= 24) {
                endTitle = new SpannableString(endTitle);
                ((SpannableString) endTitle).setSpan(new ForegroundColorSpan(-769226), 0, endTitle.length(), 0);
            }
            PendingIntent endPendingIntent = PendingIntent.getBroadcast(getParentActivity(), 0, endIntent, C.ENCODING_PCM_MU_LAW);
            builder.addAction(R.drawable.ic_call_end_white_24dp, endTitle, endPendingIntent);
            Intent answerIntent = new Intent(getParentActivity(), (Class<?>) VoIPActionsReceiver.class);
            answerIntent.setAction(getParentActivity().getPackageName() + ".AGREE_CONTACT_APPLY");
            answerIntent.putExtra("call_id", 111);
            CharSequence answerTitle = LocaleController.getString("Agree", R.string.Agree);
            if (Build.VERSION.SDK_INT >= 24) {
                answerTitle = new SpannableString(answerTitle);
                ((SpannableString) answerTitle).setSpan(new ForegroundColorSpan(-16733696), 0, answerTitle.length(), 0);
            }
            PendingIntent answerPendingIntent = PendingIntent.getBroadcast(getParentActivity(), 0, answerIntent, C.ENCODING_PCM_MU_LAW);
            builder.addAction(R.drawable.ic_call, answerTitle, answerPendingIntent);
            builder.setPriority(2);
            if (Build.VERSION.SDK_INT >= 21) {
                builder.setColor(-13851168);
                builder.setVibrate(new long[0]);
                builder.setCategory(NotificationCompat.CATEGORY_CALL);
                builder.setFullScreenIntent(PendingIntent.getActivity(getParentActivity(), 0, intent, 0), true);
                builder.addPerson("tel:" + user.phone);
            }
        }
        getNotificationsController().getNotificationManager().notify(10111213, builder.build());
    }

    public void updateTite(String titleOverlayText, int titleOverlayTextId, Runnable action) {
        if (this.fragmentsCache != null) {
            for (int i = 0; i < this.fragmentsCache.size(); i++) {
                BaseFmts f = this.fragmentsCache.get(Integer.valueOf(i));
                if (f != null && f.getActionBar() != null && f.isAdded()) {
                    f.getActionBar().setTitleOverlayText2(titleOverlayText, titleOverlayTextId, action);
                }
            }
        }
    }

    private void getFcUnRead() {
    }

    private void getFcUrlFromServer() {
    }

    private void callBackFragmentsLifeCycle(boolean isResume) {
        if (this.fragmentsCache != null) {
            for (int i = 0; i < this.fragmentsCache.size(); i++) {
                BaseFmts f = this.fragmentsCache.get(Integer.valueOf(i));
                if (f != null && f.isAdded()) {
                    if (isResume) {
                        f.onResumeForBaseFragment();
                    } else {
                        f.onPauseForBaseFragment();
                    }
                }
            }
        }
    }

    private BaseFmts getChildFragment(int position) {
        BaseVPAdapter baseVPAdapter = this.adapter;
        if (baseVPAdapter != null) {
            Fragment f = baseVPAdapter.getItem(position);
            if (f instanceof BaseFmts) {
                return (BaseFmts) f;
            }
            return null;
        }
        return null;
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    protected void onTransitionAnimationEnd(boolean isOpen, boolean backward) {
        super.onTransitionAnimationEnd(isOpen, backward);
    }

    @Override // im.uwrkaxlmjj.messenger.NotificationCenter.NotificationCenterDelegate
    public void didReceivedNotification(int id, int account, Object... args) {
        if (id != NotificationCenter.userFriendsCircleUpdate) {
            if (id == NotificationCenter.contactApplyUpdateCount) {
                if (this.mBottomBarLayout != null) {
                    int count = ((Integer) args[0]).intValue();
                    this.mBottomBarLayout.setUnread(1, count);
                    if (count == 0) {
                        NotificationManager nm = (NotificationManager) getParentActivity().getSystemService("notification");
                        nm.cancel(10111213);
                        return;
                    } else {
                        TLRPC.User currentUser = getUserConfig().getCurrentUser();
                        showIncomingNotification(UserObject.getName(currentUser), LocaleController.getString("NewContactApply", R.string.NewContactApply), null, getUserConfig().getCurrentUser(), true);
                        return;
                    }
                }
                return;
            }
            if (id == NotificationCenter.userFullInfoDidLoad && getUserConfig().isClientActivated()) {
                int userId = ((Integer) args[0]).intValue();
                if (userId == getUserConfig().getClientUserId() && (args[1] instanceof TLRPCContacts.CL_userFull_v1)) {
                    this.mIsGettingFullUserInfo = false;
                }
            }
        }
    }

    private void checkHadCompletedUserInfo(TLRPC.UserFull full) {
        if (!getUserConfig().isClientActivated() || this.mIsGettingFullUserInfo || this.mUserInfoIsCompleted) {
            return;
        }
        if (getParentLayout() != null && getParentLayout().fragmentsStack != null) {
            for (BaseFragment f : getParentLayout().fragmentsStack) {
                if (ChangePersonalInformationActivity.class.getName().equals(f.getClass().getName())) {
                    return;
                }
            }
        }
        this.mIsGettingFullUserInfo = true;
        if (full == null) {
            full = MessagesController.getInstance(this.currentAccount).getUserFull(getUserConfig().getClientUserId());
        }
        if (full instanceof TLRPCContacts.CL_userFull_v1) {
            TLRPCContacts.CL_userFull_v1 userInfo = (TLRPCContacts.CL_userFull_v1) full;
            if (userInfo.getExtendBean() != null) {
                if (userInfo.getExtendBean().needCompletedUserInfor()) {
                    AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$IndexActivity$5ya239yfPUZ-YHZSHbv0At-eSXg
                        @Override // java.lang.Runnable
                        public final void run() {
                            this.f$0.lambda$checkHadCompletedUserInfo$4$IndexActivity();
                        }
                    }, 1000L);
                    this.mIsGettingFullUserInfo = false;
                    return;
                } else {
                    this.mIsGettingFullUserInfo = false;
                    this.mUserInfoIsCompleted = true;
                    return;
                }
            }
            return;
        }
        if (full == null) {
            MessagesController.getInstance(this.currentAccount).loadFullUser(getUserConfig().getClientUserId(), this.classGuid, true);
        }
    }

    public /* synthetic */ void lambda$checkHadCompletedUserInfo$4$IndexActivity() {
        presentFragment(new ChangePersonalInformationActivity(this.currentAccount));
        this.mIsGettingFullUserInfo = false;
    }

    private void getDiscoveryData() {
        TLRPC2.TL_DiscoveryPageSetting tL_DiscoveryPageSetting;
        Log.d("bond", "getDiscoveryData");
        if (this.mBottomBarLayout.getChildCount() == 4 && (tL_DiscoveryPageSetting = this.discoveryData) != null && !tL_DiscoveryPageSetting.getS().isEmpty()) {
            BaseVPAdapter baseVPAdapter = this.adapter;
            if (baseVPAdapter != null) {
                baseVPAdapter.notifyDataSetChanged();
            }
            updateBottomItem();
        }
        TLRPC2.TL_GetDiscoveryPageSetting req = new TLRPC2.TL_GetDiscoveryPageSetting();
        req.tag = "Sbcc";
        FileLog.d(TAG, "start getData");
        ConnectionsManager connectionsManager = getConnectionsManager();
        int iSendRequest = getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$IndexActivity$Zp9r8qkgD18n2BYrWq-MUfdJ45E
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                this.f$0.lambda$getDiscoveryData$6$IndexActivity(tLObject, tL_error);
            }
        });
        this.reqDisToken = iSendRequest;
        connectionsManager.bindRequestToGuid(iSendRequest, this.classGuid);
    }

    public /* synthetic */ void lambda$getDiscoveryData$6$IndexActivity(final TLObject response, final TLRPC.TL_error error) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.-$$Lambda$IndexActivity$4ZnZU6IwCQV0fZI_tRE83S3RbjA
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$5$IndexActivity(error, response);
            }
        });
    }

    public /* synthetic */ void lambda$null$5$IndexActivity(TLRPC.TL_error error, TLObject response) {
        if (error == null && (response instanceof TLRPC2.TL_DiscoveryPageSetting)) {
            Log.d("bond", "getDiscoveryData 成功");
            this.discoveryData = (TLRPC2.TL_DiscoveryPageSetting) response;
            BaseVPAdapter baseVPAdapter = this.adapter;
            if (baseVPAdapter != null) {
                baseVPAdapter.notifyDataSetChanged();
            }
            updateBottomItem();
            FileLog.d(TAG, "getData success.");
        } else if (error != null) {
            WalletErrorUtil.parseErrorToast(error.text);
            FileLog.e(TAG, "getData error:" + error.text);
        }
        this.reqDisToken = 0;
    }

    @Override // im.uwrkaxlmjj.ui.fragments.DiscoveryFragment.Delegate
    public TLRPC2.TL_DiscoveryPageSetting getDiscoveryPageData() {
        return this.discoveryData;
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    protected void clearViews() {
        super.clearViews();
        this.mVpContent = null;
        this.mBottomBarLayout = null;
        LruCache<Integer, BaseFmts> lruCache = this.fragmentsCache;
        if (lruCache != null) {
            lruCache.evictAll();
        }
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public boolean onBackPressed() {
        BaseFmts baseFmts;
        int currentItem = this.mBottomBarLayout.getCurrentItem();
        LruCache<Integer, BaseFmts> lruCache = this.fragmentsCache;
        if (lruCache != null && ((baseFmts = lruCache.get(Integer.valueOf(currentItem))) == null || baseFmts.onBackPressed())) {
            return false;
        }
        return super.onBackPressed();
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onFragmentDestroy() {
        super.onFragmentDestroy();
        NotificationCenter.getGlobalInstance().removeObserver(this, NotificationCenter.didSetPasscode);
        NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.contactApplyUpdateCount);
        NotificationCenter.getGlobalInstance().removeObserver(this, NotificationCenter.appDidLogout);
        NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.userFriendsCircleUpdate);
        NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.userFullInfoDidLoad);
        LruCache<Integer, BaseFmts> lruCache = this.fragmentsCache;
        if (lruCache != null) {
            lruCache.evictAll();
            this.fragmentsCache = null;
        }
        BaseVPAdapter baseVPAdapter = this.adapter;
        if (baseVPAdapter != null) {
            baseVPAdapter.destroy();
            this.adapter = null;
        }
        this.mVpContent = null;
        this.mBottomBarLayout = null;
        this.discoveryData = null;
        Log.d("bond", "onFragmentDestroy");
        RxHelper.getInstance().lambda$sendSimpleRequest$0$RxHelper(TAG);
    }

    @Override // im.uwrkaxlmjj.ui.fragments.onRefreshMainInterface
    public void onRefreshMain() {
        getDiscoveryData();
    }
}
