package im.uwrkaxlmjj.ui.hui.contacts;

import android.content.Context;
import android.view.View;
import android.widget.FrameLayout;
import androidx.recyclerview.widget.DefaultItemAnimator;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.messenger.NotificationCenter;
import im.uwrkaxlmjj.tgnet.RequestDelegate;
import im.uwrkaxlmjj.tgnet.TLObject;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.tgnet.TLRPCContacts;
import im.uwrkaxlmjj.ui.actionbar.ActionBar;
import im.uwrkaxlmjj.ui.actionbar.ActionBarMenu;
import im.uwrkaxlmjj.ui.actionbar.BaseFragment;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.components.LayoutHelper;
import im.uwrkaxlmjj.ui.hui.adapter.grouping.Artist;
import im.uwrkaxlmjj.ui.hui.adapter.grouping.Genre;
import im.uwrkaxlmjj.ui.hui.adapter.grouping.GenreAdapter;
import im.uwrkaxlmjj.ui.hviews.MryEmptyView;
import im.uwrkaxlmjj.ui.hviews.MryTextView;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class MyGroupingActivity extends BaseFragment implements NotificationCenter.NotificationCenterDelegate {
    private static final int item_mgr = 1;
    private GenreAdapter adapter;
    private int contactsHash;
    private MryEmptyView emptyView;
    private ArrayList<Genre> genres = new ArrayList<>();
    private GroupingMgrActivity groupingMgrActivity;
    private RecyclerView rcvList;
    private MryTextView tvMgrView;

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public boolean onFragmentCreate() {
        NotificationCenter.getInstance(this.currentAccount).addObserver(this, NotificationCenter.groupingChanged);
        return super.onFragmentCreate();
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onFragmentDestroy() {
        NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.groupingChanged);
        super.onFragmentDestroy();
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public View createView(Context context) {
        this.fragmentView = new FrameLayout(context);
        this.fragmentView.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundGray));
        useButterKnife();
        initActionbar();
        initEmptyView();
        initView();
        initData();
        return this.fragmentView;
    }

    private void initActionbar() {
        this.actionBar.setCastShadows(false);
        this.actionBar.setTitle(LocaleController.getString("MyGrouping", R.string.MyGrouping));
        this.actionBar.setBackButtonImage(R.id.ic_back);
        this.actionBar.setActionBarMenuOnItemClick(new ActionBar.ActionBarMenuOnItemClick() { // from class: im.uwrkaxlmjj.ui.hui.contacts.MyGroupingActivity.1
            @Override // im.uwrkaxlmjj.ui.actionbar.ActionBar.ActionBarMenuOnItemClick
            public void onItemClick(int id) {
                if (id == -1) {
                    MyGroupingActivity.this.finishFragment();
                    return;
                }
                if (id == 1) {
                    MyGroupingActivity.this.groupingMgrActivity = new GroupingMgrActivity();
                    MyGroupingActivity.this.groupingMgrActivity.setGenres(MyGroupingActivity.this.genres);
                    MyGroupingActivity myGroupingActivity = MyGroupingActivity.this;
                    myGroupingActivity.presentFragment(myGroupingActivity.groupingMgrActivity);
                }
            }
        });
        ActionBarMenu menu = this.actionBar.createMenu();
        MryTextView mryTextView = new MryTextView(getParentActivity());
        this.tvMgrView = mryTextView;
        mryTextView.setText(LocaleController.getString("fc_my_manage", R.string.fc_my_manage));
        this.tvMgrView.setTextSize(1, 14.0f);
        this.tvMgrView.setTypeface(AndroidUtilities.getTypeface("fonts/rmedium.ttf"));
        this.tvMgrView.setTextColor(Theme.getColor(Theme.key_actionBarDefaultTitle));
        this.tvMgrView.setGravity(16);
        menu.addItemView(1, this.tvMgrView);
    }

    private void initEmptyView() {
        MryEmptyView mryEmptyView = new MryEmptyView(getParentActivity());
        this.emptyView = mryEmptyView;
        mryEmptyView.attach(this);
        this.emptyView.setEmptyText(LocaleController.getString(R.string.NoGrouping));
        this.emptyView.setEmptyResId(R.id.img_empty_default);
        this.emptyView.setErrorResId(R.id.img_empty_default);
        this.emptyView.setOnEmptyClickListener(new MryEmptyView.OnEmptyOrErrorClickListener() { // from class: im.uwrkaxlmjj.ui.hui.contacts.-$$Lambda$MyGroupingActivity$cSVd-W34nfHnvBQYOKQ5bnNLtBI
            @Override // im.uwrkaxlmjj.ui.hviews.MryEmptyView.OnEmptyOrErrorClickListener
            public final boolean onEmptyViewButtonClick(boolean z) {
                return this.f$0.lambda$initEmptyView$0$MyGroupingActivity(z);
            }
        });
    }

    public /* synthetic */ boolean lambda$initEmptyView$0$MyGroupingActivity(boolean isEmptyButton) {
        getContacts();
        return false;
    }

    private void initView() {
        RecyclerView recyclerView = new RecyclerView(getParentActivity());
        this.rcvList = recyclerView;
        RecyclerView.ItemAnimator animator = recyclerView.getItemAnimator();
        if (animator instanceof DefaultItemAnimator) {
            ((DefaultItemAnimator) animator).setSupportsChangeAnimations(false);
        }
        this.rcvList.setLayoutManager(new LinearLayoutManager(getParentActivity()));
        this.rcvList.setOverScrollMode(2);
        RecyclerView recyclerView2 = this.rcvList;
        GenreAdapter genreAdapter = new GenreAdapter(this.genres, this);
        this.adapter = genreAdapter;
        recyclerView2.setAdapter(genreAdapter);
        this.rcvList.setBackground(Theme.createRoundRectDrawable(AndroidUtilities.dp(5.0f), Theme.getColor(Theme.key_windowBackgroundWhite)));
        ((FrameLayout) this.fragmentView).addView(this.rcvList, LayoutHelper.createFrame(-1.0f, -2.0f, 51, 10.0f, 10.0f, 10.0f, 10.0f));
    }

    private void initData() {
        getContacts();
    }

    public void getContacts() {
        this.emptyView.showLoading();
        TLRPCContacts.TL_getContactsV1 req = new TLRPCContacts.TL_getContactsV1();
        req.hash = this.contactsHash;
        getConnectionsManager().bindRequestToGuid(getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.hui.contacts.-$$Lambda$MyGroupingActivity$zLbRo2KJVRhNFanl4uC_8HdPgwU
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                this.f$0.lambda$getContacts$2$MyGroupingActivity(tLObject, tL_error);
            }
        }), this.classGuid);
    }

    public /* synthetic */ void lambda$getContacts$2$MyGroupingActivity(final TLObject response, final TLRPC.TL_error error) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.contacts.-$$Lambda$MyGroupingActivity$GwGZYvM44J5f3_bl96ct_4VwhVE
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$1$MyGroupingActivity(error, response);
            }
        });
    }

    public /* synthetic */ void lambda$null$1$MyGroupingActivity(TLRPC.TL_error error, TLObject response) {
        if (error == null) {
            if (response instanceof TLRPCContacts.TL_contactsV1) {
                TLRPCContacts.TL_contactsV1 contacts = (TLRPCContacts.TL_contactsV1) response;
                this.contactsHash = contacts.hash;
                if (!contacts.users.isEmpty()) {
                    for (TLRPC.User user : contacts.users) {
                        getMessagesController().putUser(user, false);
                    }
                }
                if (contacts.group_infos.isEmpty()) {
                    this.emptyView.showEmpty();
                    return;
                } else {
                    makeGenres(contacts);
                    this.emptyView.showContent();
                    return;
                }
            }
            return;
        }
        this.emptyView.showError(error.text);
    }

    private void makeGenres(TLRPCContacts.TL_contactsV1 contacts) {
        GenreAdapter genreAdapter = this.adapter;
        if (genreAdapter != null) {
            genreAdapter.storeExpandState();
        }
        this.genres.clear();
        List<TLRPCContacts.TL_contactsGroupInfo> groupInfoList = contacts.group_infos;
        List<TLRPC.Contact> contactsList = contacts.contacts;
        for (TLRPCContacts.TL_contactsGroupInfo groupInfo : groupInfoList) {
            List<Artist> artists = new ArrayList<>();
            for (TLRPC.Contact contact : contactsList) {
                if (contact instanceof TLRPCContacts.TL_contactV1) {
                    TLRPCContacts.TL_contactV1 contactV1 = (TLRPCContacts.TL_contactV1) contact;
                    if (groupInfo.group_id == contactV1.group_id && getMessagesController().getUser(Integer.valueOf(contactV1.user_id)) != null) {
                        artists.add(new Artist(contactV1.user_id));
                    }
                }
            }
            Collections.sort(artists, new Comparator() { // from class: im.uwrkaxlmjj.ui.hui.contacts.-$$Lambda$MyGroupingActivity$kBtyFU8-WVuvbZW7AqIL18ZYySc
                @Override // java.util.Comparator
                public final int compare(Object obj, Object obj2) {
                    return this.f$0.lambda$makeGenres$3$MyGroupingActivity((Artist) obj, (Artist) obj2);
                }
            });
            this.genres.add(new Genre(groupInfo, artists));
        }
        Collections.sort(this.genres, new Comparator() { // from class: im.uwrkaxlmjj.ui.hui.contacts.-$$Lambda$MyGroupingActivity$c6ZJ-KXVtCyGnZcqs5HM0IZaFV8
            @Override // java.util.Comparator
            public final int compare(Object obj, Object obj2) {
                return Integer.compare(((Genre) obj).getOrderId(), ((Genre) obj2).getOrderId());
            }
        });
        GenreAdapter genreAdapter2 = this.adapter;
        if (genreAdapter2 != null) {
            genreAdapter2.restoreExpandState();
            this.adapter.notifyDataSetChanged();
        }
        GroupingMgrActivity groupingMgrActivity = this.groupingMgrActivity;
        if (groupingMgrActivity != null) {
            groupingMgrActivity.setGenres(this.genres);
        }
    }

    public /* synthetic */ int lambda$makeGenres$3$MyGroupingActivity(Artist o1, Artist o2) {
        TLRPC.User user1 = getMessagesController().getUser(Integer.valueOf(o1.getUserId()));
        TLRPC.User user2 = getMessagesController().getUser(Integer.valueOf(o2.getUserId()));
        return Integer.compare(user2.status.expires, user1.status.expires);
    }

    @Override // im.uwrkaxlmjj.messenger.NotificationCenter.NotificationCenterDelegate
    public void didReceivedNotification(int id, int account, Object... args) {
        if (id == NotificationCenter.groupingChanged) {
            getContacts();
        }
    }
}
