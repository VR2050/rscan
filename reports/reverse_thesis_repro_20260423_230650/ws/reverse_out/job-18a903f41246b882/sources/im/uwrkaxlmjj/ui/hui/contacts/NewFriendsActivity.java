package im.uwrkaxlmjj.ui.hui.contacts;

import android.content.Context;
import android.content.DialogInterface;
import android.graphics.drawable.ColorDrawable;
import android.graphics.drawable.Drawable;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.MotionEvent;
import android.view.View;
import android.view.ViewGroup;
import android.widget.LinearLayout;
import android.widget.RelativeLayout;
import android.widget.TextView;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import butterknife.BindView;
import com.google.android.exoplayer2.trackselection.AdaptiveTrackSelection;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.ImageLocation;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.messenger.MessagesController;
import im.uwrkaxlmjj.messenger.NotificationCenter;
import im.uwrkaxlmjj.messenger.UserObject;
import im.uwrkaxlmjj.tgnet.ConnectionsManager;
import im.uwrkaxlmjj.tgnet.RequestDelegate;
import im.uwrkaxlmjj.tgnet.TLObject;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.tgnet.TLRPCContacts;
import im.uwrkaxlmjj.ui.actionbar.ActionBar;
import im.uwrkaxlmjj.ui.actionbar.ActionBarMenu;
import im.uwrkaxlmjj.ui.actionbar.BaseFragment;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.actionbar.XAlertDialog;
import im.uwrkaxlmjj.ui.cells.DividerCell;
import im.uwrkaxlmjj.ui.components.AlertsCreator;
import im.uwrkaxlmjj.ui.components.AvatarDrawable;
import im.uwrkaxlmjj.ui.components.BackupImageView;
import im.uwrkaxlmjj.ui.components.RadialProgressView;
import im.uwrkaxlmjj.ui.components.RecyclerListView;
import im.uwrkaxlmjj.ui.components.toast.ToastUtils;
import im.uwrkaxlmjj.ui.decoration.StickyDecoration;
import im.uwrkaxlmjj.ui.decoration.listener.GroupListener;
import im.uwrkaxlmjj.ui.hui.chats.NewProfileActivity;
import im.uwrkaxlmjj.ui.hui.wallet_public.utils.WalletDialogUtil;
import im.uwrkaxlmjj.ui.hviews.MryRoundButton;
import im.uwrkaxlmjj.ui.hviews.MryTextView;
import im.uwrkaxlmjj.ui.hviews.dialogs.XDialog;
import im.uwrkaxlmjj.ui.hviews.slidemenu.SwipeLayout;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.Iterator;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class NewFriendsActivity extends BaseFragment implements NotificationCenter.NotificationCenterDelegate {
    private ListAdapter adapter;

    @BindView(R.attr.emptyLayout)
    LinearLayout emptyLayout;

    @BindView(R.attr.listview)
    RecyclerListView listview;

    @BindView(R.attr.progressBar)
    RadialProgressView progressBar;
    private boolean searchWas;
    private boolean searching;

    @BindView(R.attr.tvEmptyText)
    MryTextView tvEmptyText;
    private final int item_add = 1;
    private ArrayList<TLRPCContacts.ContactApplyInfo> contactsApplyInfos = new ArrayList<>();
    private ArrayList<TLRPC.User> users = new ArrayList<>();
    private HashMap<Integer, TLRPC.User> userMap = new HashMap<>();
    private HashMap<String, ArrayList<TLRPCContacts.ContactApplyInfo>> map = new HashMap<>();
    private ArrayList<String> mapKeysList = new ArrayList<>();

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public boolean onFragmentCreate() {
        super.onFragmentCreate();
        notifyServerClearUnread();
        getMessagesController().handleUpdatesContactsApply(0);
        getNotificationCenter().postNotificationName(NotificationCenter.contactApplyUpdateCount, 0);
        getMessagesController().getContactsApplyDifferenceV2(true, true, false);
        NotificationCenter.getInstance(this.currentAccount).addObserver(this, NotificationCenter.contactApplyUpdateState);
        NotificationCenter.getInstance(this.currentAccount).addObserver(this, NotificationCenter.contactApplyUpdateReceived);
        NotificationCenter.getInstance(this.currentAccount).addObserver(this, NotificationCenter.contactApplieReceived);
        getNotificationCenter().addObserver(this, NotificationCenter.contactApplyUpdateCount);
        return true;
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public void onFragmentDestroy() {
        super.onFragmentDestroy();
        NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.contactApplyUpdateState);
        NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.contactApplyUpdateReceived);
        NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.contactApplieReceived);
        NotificationCenter.getInstance(this.currentAccount).removeObserver(this, NotificationCenter.contactApplyUpdateCount);
        getMessagesController().handleUpdatesContactsApply(0);
        getNotificationCenter().postNotificationName(NotificationCenter.contactApplyUpdateCount, 0);
    }

    private void groupingApplyInfos(ArrayList<TLRPCContacts.ContactApplyInfo> applyInfos) {
        if (applyInfos == null) {
            return;
        }
        this.mapKeysList.clear();
        this.map.clear();
        Collections.sort(applyInfos, new Comparator() { // from class: im.uwrkaxlmjj.ui.hui.contacts.-$$Lambda$NewFriendsActivity$z7ej33n-vdFjDQ_BD5YiOGIhPOI
            @Override // java.util.Comparator
            public final int compare(Object obj, Object obj2) {
                return Integer.compare(((TLRPCContacts.ContactApplyInfo) obj2).date, ((TLRPCContacts.ContactApplyInfo) obj).date);
            }
        });
        for (TLRPCContacts.ContactApplyInfo item : applyInfos) {
            if (getConnectionsManager().getCurrentTime() - item.date < 259200) {
                ArrayList<TLRPCContacts.ContactApplyInfo> in = this.map.get("in");
                if (in == null) {
                    in = new ArrayList<>();
                    this.map.put("in", in);
                    this.mapKeysList.add("in");
                }
                in.add(item);
            } else {
                ArrayList<TLRPCContacts.ContactApplyInfo> out = this.map.get("out");
                if (out == null) {
                    out = new ArrayList<>();
                    this.map.put("out", out);
                    this.mapKeysList.add("out");
                }
                out.add(item);
            }
        }
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public View createView(Context context) {
        this.fragmentView = LayoutInflater.from(context).inflate(R.layout.activity_new_friend_layout, (ViewGroup) null, false);
        this.fragmentView.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundGray));
        useButterKnife();
        super.createView(context);
        initActionbar();
        initProgressBar();
        initList();
        return this.fragmentView;
    }

    private void initActionbar() {
        this.actionBar.setTitle(LocaleController.getString("NewFriends", R.string.NewFriends));
        this.actionBar.setBackButtonImage(R.id.ic_back);
        this.actionBar.setCastShadows(false);
        this.actionBar.setActionBarMenuOnItemClick(new ActionBar.ActionBarMenuOnItemClick() { // from class: im.uwrkaxlmjj.ui.hui.contacts.NewFriendsActivity.1
            @Override // im.uwrkaxlmjj.ui.actionbar.ActionBar.ActionBarMenuOnItemClick
            public void onItemClick(int id) {
                if (id == -1) {
                    NewFriendsActivity.this.finishFragment();
                } else if (id == 1) {
                    NewFriendsActivity.this.presentFragment(new AddContactsActivity());
                }
            }
        });
        ActionBarMenu menu = this.actionBar.createMenu();
        MryTextView tvAddView = new MryTextView(getParentActivity());
        tvAddView.setText(LocaleController.getString("Add", R.string.Add));
        tvAddView.setTextSize(1, 14.0f);
        tvAddView.setTypeface(AndroidUtilities.getTypeface("fonts/rmedium.ttf"));
        tvAddView.setTextColor(Theme.getColor(Theme.key_actionBarDefaultTitle));
        tvAddView.setGravity(16);
        menu.addItemView(1, tvAddView);
    }

    private void initProgressBar() {
        this.progressBar.setSize(AndroidUtilities.dp(28.0f));
        this.progressBar.setProgressColor(Theme.getColor(Theme.key_chat_serviceText));
        this.progressBar.setBackgroundResource(R.drawable.system_loader);
        this.progressBar.getBackground().setColorFilter(Theme.colorFilter);
    }

    private void initList() {
        this.tvEmptyText.setTextColor(Theme.key_windowBackgroundWhiteGrayText6);
        this.listview.setHasFixedSize(true);
        this.listview.setVerticalScrollBarEnabled(false);
        this.listview.setLayoutManager(new LinearLayoutManager(this.fragmentView.getContext()));
        ListAdapter listAdapter = new ListAdapter(this.fragmentView.getContext());
        this.adapter = listAdapter;
        listAdapter.setList(this.mapKeysList, this.map, true);
        StickyDecoration.Builder decorationBuilder = StickyDecoration.Builder.init(new GroupListener() { // from class: im.uwrkaxlmjj.ui.hui.contacts.-$$Lambda$NewFriendsActivity$4Ygt8N0lwhqe2Ry3Q9ny59UQdg0
            @Override // im.uwrkaxlmjj.ui.decoration.listener.GroupListener
            public final String getGroupName(int i) {
                return this.f$0.lambda$initList$1$NewFriendsActivity(i);
            }
        }).setOffset(1).setGroupBackground(Theme.getColor(Theme.key_windowBackgroundGray)).setGroupTextColor(Theme.getColor(Theme.key_list_decorationTextColor)).setGroupTextTypeface(AndroidUtilities.getTypeface("fonts/rmedium.ttf")).setGroupHeight(AndroidUtilities.dp(38.5f)).setGroupTextSize(AndroidUtilities.dp(14.0f)).setTextSideMargin(AndroidUtilities.dp(15.0f));
        StickyDecoration decoration = decorationBuilder.build();
        this.listview.addItemDecoration(decoration);
        this.listview.setDisableHighlightState(true);
        this.listview.setAdapter(this.adapter);
        this.listview.setOnItemClickListener(new RecyclerListView.OnItemClickListener() { // from class: im.uwrkaxlmjj.ui.hui.contacts.-$$Lambda$NewFriendsActivity$l3GnsZ7iJaJqwvb--opGdlwibIE
            @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.OnItemClickListener
            public final void onItemClick(View view, int i) {
                this.f$0.lambda$initList$2$NewFriendsActivity(view, i);
            }
        });
        this.listview.addOnScrollListener(new RecyclerView.OnScrollListener() { // from class: im.uwrkaxlmjj.ui.hui.contacts.NewFriendsActivity.2
            private boolean scrollingManually;

            @Override // androidx.recyclerview.widget.RecyclerView.OnScrollListener
            public void onScrollStateChanged(RecyclerView recyclerView, int newState) {
                if (newState == 1) {
                    if (NewFriendsActivity.this.searching && NewFriendsActivity.this.searchWas) {
                        AndroidUtilities.hideKeyboard(NewFriendsActivity.this.getParentActivity().getCurrentFocus());
                    }
                    this.scrollingManually = true;
                    return;
                }
                this.scrollingManually = false;
            }

            @Override // androidx.recyclerview.widget.RecyclerView.OnScrollListener
            public void onScrolled(RecyclerView recyclerView, int dx, int dy) {
                super.onScrolled(recyclerView, dx, dy);
            }
        });
        this.adapter.notifyDataSetChanged();
    }

    public /* synthetic */ String lambda$initList$1$NewFriendsActivity(int position) {
        int i;
        String str;
        if (this.adapter.getItemCount() > position && position > -1) {
            String letter = this.adapter.getLetter(position);
            if (letter != null) {
                if ("in".equals(letter)) {
                    i = R.string.new_friends_three_days;
                    str = "new_friends_three_days";
                } else {
                    i = R.string.new_friends_three_days_before;
                    str = "new_friends_three_days_before";
                }
                return LocaleController.getString(str, i);
            }
            return letter;
        }
        return null;
    }

    public /* synthetic */ void lambda$initList$2$NewFriendsActivity(View view, int position) {
        int section = this.adapter.getSectionForPosition(position);
        if (section != 0) {
            int pos = this.adapter.getPositionInSectionForPosition(position);
            Object item = this.adapter.getItem(section, pos);
            if (item instanceof TLRPCContacts.ContactApplyInfo) {
                TLRPCContacts.ContactApplyInfo info = (TLRPCContacts.ContactApplyInfo) item;
                TLRPC.User user = getMessagesController().getUser(Integer.valueOf(info.from_peer.user_id));
                if (user != null) {
                    Bundle bundle = new Bundle();
                    if (user.contact) {
                        bundle.putInt("user_id", user.id);
                        presentFragment(new NewProfileActivity(bundle));
                        return;
                    }
                    bundle.putInt("from_type", 7);
                    bundle.putInt("req_state", info.state);
                    bundle.putInt("apply_id", info.id);
                    bundle.putInt("expire", info.expire);
                    bundle.putString("greet", info.greet);
                    presentFragment(new AddContactsInfoActivity(bundle, user));
                }
            }
        }
    }

    @Override // im.uwrkaxlmjj.messenger.NotificationCenter.NotificationCenterDelegate
    public void didReceivedNotification(int id, int account, Object... args) {
        if (id == NotificationCenter.contactApplyUpdateState) {
            int apply_id = ((Integer) args[0]).intValue();
            int state = ((Integer) args[1]).intValue();
            int index = getIndex(apply_id);
            ArrayList<TLRPCContacts.ContactApplyInfo> arrayList = this.contactsApplyInfos;
            if (arrayList != null) {
                arrayList.get(index).state = state;
                groupingApplyInfos(this.contactsApplyInfos);
                ListAdapter listAdapter = this.adapter;
                if (listAdapter != null) {
                    listAdapter.setList(this.mapKeysList, this.map, false);
                    this.adapter.notifyDataSetChanged();
                    return;
                }
                return;
            }
            return;
        }
        if (id == NotificationCenter.contactApplyUpdateReceived) {
            TLRPCContacts.ContactApplyInfo recvInfo = (TLRPCContacts.ContactApplyInfo) args[0];
            if (this.contactsApplyInfos != null) {
                int i = 0;
                while (true) {
                    if (i >= this.contactsApplyInfos.size()) {
                        break;
                    }
                    TLRPCContacts.ContactApplyInfo info = this.contactsApplyInfos.get(i);
                    if (recvInfo.from_peer.user_id != info.from_peer.user_id) {
                        i++;
                    } else {
                        this.contactsApplyInfos.remove(i);
                        break;
                    }
                }
                this.contactsApplyInfos.add(0, recvInfo);
                groupingApplyInfos(this.contactsApplyInfos);
                ListAdapter listAdapter2 = this.adapter;
                if (listAdapter2 != null) {
                    listAdapter2.setList(this.mapKeysList, this.map, false);
                    this.adapter.notifyDataSetChanged();
                }
                getMessagesController().handleUpdatesContactsApply(0);
                getNotificationCenter().postNotificationName(NotificationCenter.contactApplyUpdateCount, 0);
                return;
            }
            return;
        }
        if (id == NotificationCenter.contactApplieReceived) {
            this.contactsApplyInfos = (ArrayList) args[0];
            ArrayList<TLRPC.User> arrayList2 = (ArrayList) args[1];
            this.users = arrayList2;
            for (TLRPC.User user : arrayList2) {
                this.userMap.put(Integer.valueOf(user.id), user);
            }
            groupingApplyInfos(this.contactsApplyInfos);
            ListAdapter listAdapter3 = this.adapter;
            if (listAdapter3 != null) {
                listAdapter3.setList(this.mapKeysList, this.map, false);
                this.adapter.notifyDataSetChanged();
                return;
            }
            return;
        }
        if (id == NotificationCenter.contactApplyUpdateCount && this.adapter != null && args != null && args.length > 0) {
            ((Integer) args[0]).intValue();
            this.adapter.isFirst = false;
            this.adapter.notifyDataSetChanged();
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    class ListAdapter extends RecyclerListView.SectionsAdapter {
        private boolean isFirst;
        private ArrayList<String> list;
        private Context mContext;
        private HashMap<String, ArrayList<TLRPCContacts.ContactApplyInfo>> updateMaps;

        void setList(ArrayList<String> list, HashMap<String, ArrayList<TLRPCContacts.ContactApplyInfo>> map, boolean isFirst) {
            this.list = list;
            this.updateMaps = map;
            this.isFirst = isFirst;
        }

        ListAdapter(Context context) {
            this.mContext = context;
        }

        @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.SectionsAdapter, androidx.recyclerview.widget.RecyclerView.Adapter
        public void notifyDataSetChanged() {
            super.notifyDataSetChanged();
            int count = super.getItemCount();
            if (this.isFirst) {
                if (NewFriendsActivity.this.progressBar.getVisibility() != 0) {
                    NewFriendsActivity.this.progressBar.setVisibility(0);
                }
            } else {
                NewFriendsActivity.this.progressBar.setVisibility(8);
                NewFriendsActivity.this.emptyLayout.setVisibility(count != 1 ? 8 : 0);
            }
        }

        @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.SectionsAdapter, androidx.recyclerview.widget.RecyclerView.Adapter
        public int getItemCount() {
            int count = 1;
            if (this.updateMaps != null) {
                for (String item : this.list) {
                    count += this.updateMaps.get(item).size();
                }
            }
            return count;
        }

        @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.SectionsAdapter
        public int getSectionCount() {
            return this.list.size() + 1;
        }

        public int getPositionForSection(int section) {
            if (section == -1) {
                return -1;
            }
            int positionStart = 0;
            int N = getSectionCount();
            for (int i = 0; i < N; i++) {
                if (i >= section) {
                    return positionStart;
                }
                int count = getCountForSection(i);
                positionStart += count;
            }
            return -1;
        }

        @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.SectionsAdapter
        public int getCountForSection(int section) {
            if (section == 0) {
                return 1;
            }
            return this.updateMaps.get(this.list.get(section - 1)).size();
        }

        @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.SectionsAdapter
        public boolean isEnabled(int section, int row) {
            return true;
        }

        @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.SectionsAdapter
        public int getItemViewType(int section, int position) {
            return section == 0 ? 0 : 1;
        }

        @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.SectionsAdapter
        public Object getItem(int section, int position) {
            if (section == 0) {
                return null;
            }
            String key = this.list.get(section - 1);
            ArrayList<TLRPCContacts.ContactApplyInfo> updates = this.updateMaps.get(key);
            return updates.get(position);
        }

        @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.SectionsAdapter
        public void onBindViewHolder(int section, int position, RecyclerView.ViewHolder holder) {
            Drawable bg;
            if (holder.getItemViewType() == 1) {
                SwipeLayout swipeLayout = (SwipeLayout) holder.itemView;
                swipeLayout.setItemWidth(AndroidUtilities.dp(65.0f));
                int radius = AndroidUtilities.dp(5.0f);
                if (getItemCount() == 1) {
                    bg = Theme.createRoundRectDrawable(radius, Theme.getColor(Theme.key_windowBackgroundWhite));
                } else if (position == 0 || position == getItemCount() - 1) {
                    if (position == 0) {
                        bg = Theme.createRoundRectDrawable(radius, radius, 0.0f, 0.0f, Theme.getColor(Theme.key_windowBackgroundWhite));
                    } else {
                        bg = Theme.createRoundRectDrawable(0.0f, 0.0f, radius, radius, Theme.getColor(Theme.key_windowBackgroundWhite));
                    }
                } else {
                    bg = new ColorDrawable(Theme.getColor(Theme.key_windowBackgroundWhite));
                }
                swipeLayout.setRightTexts(LocaleController.getString(R.string.Delete));
                swipeLayout.setRightColors(Theme.getColor(Theme.key_chat_inRedCall));
                swipeLayout.setRightTextColors(-1);
                swipeLayout.setTextSize(AndroidUtilities.sp2px(12.0f));
                swipeLayout.setCanFullSwipeFromRight(false);
                swipeLayout.setCanFullSwipeFromLeft(false);
                swipeLayout.setAutoHideSwipe(true);
                swipeLayout.setOnlyOneSwipe(true);
                swipeLayout.rebuildLayout();
                RelativeLayout rlMainLayout = (RelativeLayout) holder.itemView.findViewById(R.attr.rlMainLayout);
                rlMainLayout.setBackground(bg);
                BackupImageView avatar = (BackupImageView) holder.itemView.findViewById(R.attr.avatarImage);
                avatar.setRoundRadius(AndroidUtilities.dp(7.5f));
                TextView nameText = (TextView) holder.itemView.findViewById(R.attr.nameText);
                TextView bioText = (TextView) holder.itemView.findViewById(R.attr.bioText);
                MryRoundButton statusBtn = (MryRoundButton) holder.itemView.findViewById(R.attr.statusText);
                statusBtn.setPrimaryRoundFillStyle(AndroidUtilities.dp(26.0f));
                statusBtn.setBackground(Theme.createRoundRectDrawable(AndroidUtilities.dp(8.0f), Theme.getColor(Theme.key_windowBackgroundWhiteBlueButton)));
                TextView statusText2 = (TextView) holder.itemView.findViewById(R.attr.statusText2);
                DividerCell divider = (DividerCell) holder.itemView.findViewById(R.attr.divider);
                nameText.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteBlackText));
                statusText2.setTextColor(-4737097);
                RelativeLayout.LayoutParams lp1 = (RelativeLayout.LayoutParams) statusBtn.getLayoutParams();
                lp1.rightMargin = AndroidUtilities.dp(5.0f);
                statusBtn.setLayoutParams(lp1);
                RelativeLayout.LayoutParams lp2 = (RelativeLayout.LayoutParams) statusText2.getLayoutParams();
                lp2.rightMargin = AndroidUtilities.dp(19.5f);
                statusText2.setLayoutParams(lp2);
                rlMainLayout.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
                if (position == getCountForSection(section) - 1) {
                    divider.setVisibility(8);
                    if (section == getSectionCount() - 1) {
                        rlMainLayout.setBackground(Theme.createRoundRectDrawable(0.0f, 0.0f, AndroidUtilities.dp(5.0f), AndroidUtilities.dp(5.0f), Theme.getColor(Theme.key_windowBackgroundWhite)));
                    }
                }
                final TLRPCContacts.ContactApplyInfo info = (TLRPCContacts.ContactApplyInfo) getItem(section, position);
                TLRPC.User user = (TLRPC.User) NewFriendsActivity.this.userMap.get(Integer.valueOf(info.from_peer.user_id));
                if (user == null) {
                    user = NewFriendsActivity.this.getMessagesController().getUser(Integer.valueOf(info.from_peer.user_id));
                }
                AvatarDrawable avatarDrawable = new AvatarDrawable(user);
                avatarDrawable.setColor(Theme.getColor(Theme.key_avatar_backgroundInProfileBlue));
                avatar.setImage(ImageLocation.getForUser(user, false), "50_50", avatarDrawable, user);
                if (user != null) {
                    nameText.setText(UserObject.getName(user));
                }
                bioText.setText(info.greet);
                if (info.state == 0) {
                    statusBtn.setText(LocaleController.getString("Agree", R.string.Agree));
                    statusBtn.setVisibility(0);
                    statusText2.setVisibility(8);
                    if (NewFriendsActivity.this.getConnectionsManager().getCurrentTime() > info.expire) {
                        statusText2.setText(LocaleController.getString("RequestExpired", R.string.RequestExpired));
                        statusBtn.setVisibility(8);
                        statusText2.setVisibility(0);
                    }
                } else if (info.state == 1) {
                    statusText2.setText(LocaleController.getString("ApplyApproved", R.string.ApplyApproved));
                    statusBtn.setVisibility(8);
                    statusText2.setVisibility(0);
                }
                swipeLayout.setOnSwipeItemClickListener(new SwipeLayout.OnSwipeItemClickListener() { // from class: im.uwrkaxlmjj.ui.hui.contacts.-$$Lambda$NewFriendsActivity$ListAdapter$GHO-bKPKBBZ2-PIUh5F5PoUkqvo
                    @Override // im.uwrkaxlmjj.ui.hviews.slidemenu.SwipeLayout.OnSwipeItemClickListener
                    public final void onSwipeItemClick(boolean z, int i) {
                        this.f$0.lambda$onBindViewHolder$2$NewFriendsActivity$ListAdapter(info, z, i);
                    }
                });
                statusBtn.getParent().requestDisallowInterceptTouchEvent(true);
                statusBtn.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.contacts.-$$Lambda$NewFriendsActivity$ListAdapter$06fnOIMp_zUrWZ-ozKoKyC9OpHo
                    @Override // android.view.View.OnClickListener
                    public final void onClick(View view) {
                        this.f$0.lambda$onBindViewHolder$9$NewFriendsActivity$ListAdapter(info, view);
                    }
                });
            }
        }

        public /* synthetic */ void lambda$onBindViewHolder$2$NewFriendsActivity$ListAdapter(final TLRPCContacts.ContactApplyInfo info, boolean left, int index) {
            XDialog.Builder builder = new XDialog.Builder(NewFriendsActivity.this.getParentActivity());
            builder.setMessage(LocaleController.getString("SureDeleteApply", R.string.SureDeleteApply));
            builder.setNegativeButton(LocaleController.getString("Cancel", R.string.Cancel), null);
            builder.setPositiveButton(LocaleController.getString("OK", R.string.OK), new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.contacts.-$$Lambda$NewFriendsActivity$ListAdapter$bAWpzIuqQFjZjMThhEaqe3ranG0
                @Override // android.content.DialogInterface.OnClickListener
                public final void onClick(DialogInterface dialogInterface, int i) {
                    this.f$0.lambda$null$0$NewFriendsActivity$ListAdapter(info, dialogInterface, i);
                }
            });
            XDialog xDialog = builder.create();
            NewFriendsActivity.this.showDialog(xDialog);
            xDialog.setOnCancelListener(new DialogInterface.OnCancelListener() { // from class: im.uwrkaxlmjj.ui.hui.contacts.-$$Lambda$NewFriendsActivity$ListAdapter$3agfVKuJkmgfvXmGRy28dviqEHw
                @Override // android.content.DialogInterface.OnCancelListener
                public final void onCancel(DialogInterface dialogInterface) {
                    this.f$0.lambda$null$1$NewFriendsActivity$ListAdapter(dialogInterface);
                }
            });
        }

        public /* synthetic */ void lambda$null$0$NewFriendsActivity$ListAdapter(TLRPCContacts.ContactApplyInfo info, DialogInterface dialog, int which) {
            ArrayList<Integer> ids = new ArrayList<>();
            ids.add(Integer.valueOf(info.id));
            NewFriendsActivity.this.deleteApplyRequest(ids);
        }

        public /* synthetic */ void lambda$null$1$NewFriendsActivity$ListAdapter(DialogInterface dialog) {
            NewFriendsActivity.this.adapter.notifyDataSetChanged();
        }

        public /* synthetic */ void lambda$onBindViewHolder$9$NewFriendsActivity$ListAdapter(final TLRPCContacts.ContactApplyInfo info, View v) {
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.contacts.-$$Lambda$NewFriendsActivity$ListAdapter$mwclpUerETGcQEUnSuS5Hk27QiA
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$null$8$NewFriendsActivity$ListAdapter(info);
                }
            });
        }

        public /* synthetic */ void lambda$null$8$NewFriendsActivity$ListAdapter(final TLRPCContacts.ContactApplyInfo info) {
            WalletDialogUtil.showWalletDialog(NewFriendsActivity.this, null, LocaleController.getString("AcceptContactTip", R.string.AcceptContactTip), LocaleController.getString("Cancel", R.string.Cancel), LocaleController.getString("OK", R.string.OK), null, new DialogInterface.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.contacts.-$$Lambda$NewFriendsActivity$ListAdapter$rRc1f4sP9rQihU43SO5r3V9RWy8
                @Override // android.content.DialogInterface.OnClickListener
                public final void onClick(DialogInterface dialogInterface, int i) {
                    this.f$0.lambda$null$7$NewFriendsActivity$ListAdapter(info, dialogInterface, i);
                }
            }, null);
        }

        public /* synthetic */ void lambda$null$7$NewFriendsActivity$ListAdapter(final TLRPCContacts.ContactApplyInfo info, DialogInterface dialogInterface, int i) {
            final XAlertDialog progressDialog = new XAlertDialog(NewFriendsActivity.this.getParentActivity(), 4);
            progressDialog.setLoadingText(LocaleController.getString(R.string.ApplyAdding));
            TLRPCContacts.AcceptContactApply req = new TLRPCContacts.AcceptContactApply();
            req.apply_id = info.id;
            req.group_id = 0;
            req.first_name = "";
            req.last_name = "";
            ConnectionsManager connectionsManager = NewFriendsActivity.this.getConnectionsManager();
            final int reqId = NewFriendsActivity.this.getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.hui.contacts.-$$Lambda$NewFriendsActivity$ListAdapter$_QbD7JfQu_C6BlIRapU5N56d4-E
                @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
                public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                    this.f$0.lambda$null$5$NewFriendsActivity$ListAdapter(progressDialog, info, tLObject, tL_error);
                }
            });
            connectionsManager.bindRequestToGuid(reqId, NewFriendsActivity.this.classGuid);
            progressDialog.setOnCancelListener(new DialogInterface.OnCancelListener() { // from class: im.uwrkaxlmjj.ui.hui.contacts.-$$Lambda$NewFriendsActivity$ListAdapter$CNlyjJmlyJN6NdlqnN4_qTwL92c
                @Override // android.content.DialogInterface.OnCancelListener
                public final void onCancel(DialogInterface dialogInterface2) {
                    this.f$0.lambda$null$6$NewFriendsActivity$ListAdapter(reqId, dialogInterface2);
                }
            });
            progressDialog.show();
        }

        public /* synthetic */ void lambda$null$5$NewFriendsActivity$ListAdapter(final XAlertDialog progressDialog, final TLRPCContacts.ContactApplyInfo info, final TLObject response, final TLRPC.TL_error error) {
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.contacts.-$$Lambda$NewFriendsActivity$ListAdapter$XHFZtEi3OxHabKxh32suc2l540c
                @Override // java.lang.Runnable
                public final void run() throws Exception {
                    this.f$0.lambda$null$4$NewFriendsActivity$ListAdapter(error, progressDialog, response, info);
                }
            });
        }

        public /* synthetic */ void lambda$null$4$NewFriendsActivity$ListAdapter(TLRPC.TL_error error, final XAlertDialog progressDialog, TLObject response, TLRPCContacts.ContactApplyInfo info) throws Exception {
            if (error != null) {
                progressDialog.dismiss();
                ToastUtils.show((CharSequence) ContactsUtils.getAboutContactsErrText(error));
                return;
            }
            TLRPC.Updates res = (TLRPC.Updates) response;
            NewFriendsActivity.this.getMessagesController().processUpdates(res, false);
            TLRPCContacts.ContactApplyInfo aInfo = new TLRPCContacts.ContactApplyInfo();
            aInfo.id = info.id;
            aInfo.state = 1;
            NewFriendsActivity.this.getNotificationCenter().postNotificationName(NotificationCenter.contactApplyUpdateState, Integer.valueOf(info.id), 1);
            progressDialog.setLoadingImage(NewFriendsActivity.this.getParentActivity().getResources().getDrawable(R.id.ic_apply_send_done), AndroidUtilities.dp(30.0f), AndroidUtilities.dp(20.0f));
            progressDialog.setLoadingText(LocaleController.getString(R.string.AddedContacts));
            NewFriendsActivity.this.fragmentView.postDelayed(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.contacts.-$$Lambda$NewFriendsActivity$ListAdapter$6gSnpWMokbbUhmwEvz8Tbz2m4tc
                @Override // java.lang.Runnable
                public final void run() {
                    progressDialog.dismiss();
                }
            }, AdaptiveTrackSelection.DEFAULT_MIN_TIME_BETWEEN_BUFFER_REEVALUTATION_MS);
        }

        public /* synthetic */ void lambda$null$6$NewFriendsActivity$ListAdapter(int reqId, DialogInterface hintDialog) {
            NewFriendsActivity.this.getConnectionsManager().cancelRequest(reqId, true);
        }

        @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.SectionsAdapter
        public View getSectionHeaderView(int section, View view) {
            return null;
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public RecyclerView.ViewHolder onCreateViewHolder(ViewGroup parent, int viewType) {
            View view = null;
            if (viewType == 0) {
                view = new View(this.mContext);
            } else if (viewType == 1) {
                view = new SwipeLayout(this.mContext) { // from class: im.uwrkaxlmjj.ui.hui.contacts.NewFriendsActivity.ListAdapter.1
                    @Override // android.view.View
                    public boolean onTouchEvent(MotionEvent event) {
                        if (isExpanded()) {
                            return true;
                        }
                        return super.onTouchEvent(event);
                    }
                };
                ((ViewGroup) view).setClipChildren(false);
                SwipeLayout swipeLayout = (SwipeLayout) view;
                View cell = LayoutInflater.from(this.mContext).inflate(R.layout.item_contacts_apply_layout, parent, false);
                swipeLayout.setUpView(cell);
                view.setLayoutParams(new RecyclerView.LayoutParams(-1, AndroidUtilities.dp(65.0f)));
            }
            return new RecyclerListView.Holder(view);
        }

        @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.FastScrollAdapter
        public String getLetter(int position) {
            int section = getSectionForPosition(position);
            if (section == 0) {
                return null;
            }
            return this.list.get(section - 1);
        }

        @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.FastScrollAdapter
        public int getPositionForScrollProgress(float progress) {
            return (int) (getItemCount() * progress);
        }
    }

    private void notifyServerClearUnread() {
        TLRPCContacts.ClearUnreadApply req = new TLRPCContacts.ClearUnreadApply();
        req.max_apply_id = MessagesController.getMainSettings(this.currentAccount).getInt("contacts_apply_id", 0);
        getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.hui.contacts.-$$Lambda$NewFriendsActivity$mDjMZKsicne1XvPAqvwsbNNrX3c
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                NewFriendsActivity.lambda$notifyServerClearUnread$3(tLObject, tL_error);
            }
        });
    }

    static /* synthetic */ void lambda$notifyServerClearUnread$3(TLObject response, TLRPC.TL_error error) {
        if (error != null) {
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void deleteApplyRequest(final ArrayList<Integer> ids) {
        TLRPCContacts.DeleteContactApply req = new TLRPCContacts.DeleteContactApply();
        TLRPCContacts.DeleteActionClearSome action = new TLRPCContacts.DeleteActionClearSome();
        action.ids = ids;
        req.action = action;
        getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.hui.contacts.-$$Lambda$NewFriendsActivity$ax6Mtxy5jCZgPtCu_w2rQnBCYW0
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                this.f$0.lambda$deleteApplyRequest$6$NewFriendsActivity(ids, tLObject, tL_error);
            }
        });
    }

    public /* synthetic */ void lambda$deleteApplyRequest$6$NewFriendsActivity(ArrayList ids, TLObject response, TLRPC.TL_error error) {
        if (error != null) {
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.contacts.-$$Lambda$NewFriendsActivity$udry_DSvtmkaTHSWGq-C9oWzeiE
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$null$4$NewFriendsActivity();
                }
            });
            return;
        }
        if (response instanceof TLRPC.TL_boolTrue) {
            Iterator it = ids.iterator();
            while (it.hasNext()) {
                Integer id = (Integer) it.next();
                int index = getIndex(id.intValue());
                if (index != -1) {
                    this.contactsApplyInfos.remove(getIndex(id.intValue()));
                }
                this.users.remove(getMessagesController().getUser(id));
            }
            AndroidUtilities.runOnUIThread(new $$Lambda$NewFriendsActivity$Y0dbntpAWzkNmMM36ZiAM0H8ud8(this));
            return;
        }
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.contacts.-$$Lambda$NewFriendsActivity$BtMyEJhwIP-iFxWP7_d3eYrFz7o
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$5$NewFriendsActivity();
            }
        });
    }

    public /* synthetic */ void lambda$null$4$NewFriendsActivity() {
        AlertsCreator.showSimpleAlert(this, LocaleController.getString("new_friends_delete_fail", R.string.new_friends_delete_fail));
    }

    public /* synthetic */ void lambda$null$5$NewFriendsActivity() {
        AlertsCreator.showSimpleAlert(this, LocaleController.getString("new_friends_delete_fail", R.string.new_friends_delete_fail));
    }

    private void deleteAllRequsts() {
        TLRPCContacts.DeleteContactApply req = new TLRPCContacts.DeleteContactApply();
        TLRPCContacts.DeleteActionClearHistory action = new TLRPCContacts.DeleteActionClearHistory();
        action.max_id = MessagesController.getMainSettings(this.currentAccount).getInt("contacts_apply_id", 0);
        req.action = action;
        getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.hui.contacts.-$$Lambda$NewFriendsActivity$PPKH_a5qQNd8lvEsKB6Q7UVr_Ts
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                this.f$0.lambda$deleteAllRequsts$9$NewFriendsActivity(tLObject, tL_error);
            }
        });
    }

    public /* synthetic */ void lambda$deleteAllRequsts$9$NewFriendsActivity(TLObject response, TLRPC.TL_error error) {
        if (error != null) {
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.contacts.-$$Lambda$NewFriendsActivity$zd54UTpzie7bA2T6hdy-685uaqI
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$null$7$NewFriendsActivity();
                }
            });
        } else {
            if (response instanceof TLRPC.TL_boolTrue) {
                this.contactsApplyInfos.clear();
                this.users.clear();
                AndroidUtilities.runOnUIThread(new $$Lambda$NewFriendsActivity$Y0dbntpAWzkNmMM36ZiAM0H8ud8(this));
                return;
            }
            AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.contacts.-$$Lambda$NewFriendsActivity$Ga8OhjoeU2ah9e6W3eU_hEjJs1I
                @Override // java.lang.Runnable
                public final void run() {
                    this.f$0.lambda$null$8$NewFriendsActivity();
                }
            });
        }
    }

    public /* synthetic */ void lambda$null$7$NewFriendsActivity() {
        AlertsCreator.showSimpleAlert(this, LocaleController.getString("new_friends_delete_fail", R.string.new_friends_delete_fail));
    }

    public /* synthetic */ void lambda$null$8$NewFriendsActivity() {
        AlertsCreator.showSimpleAlert(this, LocaleController.getString("new_friends_delete_fail", R.string.new_friends_delete_fail));
    }

    /* JADX INFO: Access modifiers changed from: private */
    public void notifyListUpdate() {
        this.userMap.clear();
        for (TLRPC.User user : this.users) {
            this.userMap.put(Integer.valueOf(user.id), user);
        }
        groupingApplyInfos(this.contactsApplyInfos);
        this.adapter.setList(this.mapKeysList, this.map, false);
        this.adapter.notifyDataSetChanged();
    }

    private int getIndex(int id) {
        if (this.contactsApplyInfos != null) {
            for (int i = 0; i < this.contactsApplyInfos.size(); i++) {
                if (this.contactsApplyInfos.get(i).id == id) {
                    return i;
                }
            }
            return -1;
        }
        return -1;
    }
}
