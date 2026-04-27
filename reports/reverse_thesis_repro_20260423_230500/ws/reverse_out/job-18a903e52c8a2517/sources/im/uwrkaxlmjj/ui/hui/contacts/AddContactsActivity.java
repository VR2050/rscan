package im.uwrkaxlmjj.ui.hui.contacts;

import android.content.Context;
import android.content.Intent;
import android.content.res.ColorStateList;
import android.graphics.PorterDuff;
import android.os.Build;
import android.os.Bundle;
import android.text.TextUtils;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.ProgressBar;
import android.widget.TextView;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import butterknife.BindView;
import com.blankj.utilcode.util.RegexUtils;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.ContactsController;
import im.uwrkaxlmjj.messenger.FileLog;
import im.uwrkaxlmjj.messenger.ImageLocation;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.tgnet.ConnectionsManager;
import im.uwrkaxlmjj.tgnet.RequestDelegate;
import im.uwrkaxlmjj.tgnet.TLObject;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.tgnet.TLRPCContacts;
import im.uwrkaxlmjj.ui.actionbar.ActionBar;
import im.uwrkaxlmjj.ui.actionbar.BaseSearchViewFragment;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.components.AvatarDrawable;
import im.uwrkaxlmjj.ui.components.BackupImageView;
import im.uwrkaxlmjj.ui.components.LayoutHelper;
import im.uwrkaxlmjj.ui.components.RecyclerListView;
import im.uwrkaxlmjj.ui.dialogs.WalletDialog;
import im.uwrkaxlmjj.ui.hui.chats.NewProfileActivity;
import im.uwrkaxlmjj.ui.hui.discovery.QrScanActivity;
import im.uwrkaxlmjj.ui.hui.mine.QrCodeActivity;
import im.uwrkaxlmjj.ui.hui.wallet_public.utils.WalletErrorUtil;
import im.uwrkaxlmjj.ui.hviews.search.MrySearchView;
import im.uwrkaxlmjj.ui.hviews.swipelist.SlidingItemMenuRecyclerView;
import java.util.ArrayList;
import java.util.List;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class AddContactsActivity extends BaseSearchViewFragment {
    private static final int ID_EMPTY_IMAGE_VIEW = 345686;
    private static final int ID_EMPTY_TEXT_VIEW = 345687;
    private static final int VIEW_TYPE_LIST_ICON = 0;
    private static final int VIEW_TYPE_LIST_SEARCHING = 3;
    private static final int VIEW_TYPE_LIST_SEARCH_EMPTY = 2;
    private static final int VIEW_TYPE_LIST_SEARCH_ERROR = 4;
    private static final int VIEW_TYPE_LIST_SEARCH_RESULT = 1;
    private int codeScan;
    private int from_type;
    private int inviteMore;
    private int lastSectionRow;

    @BindView(R.attr.llSearchLayout)
    LinearLayout llSearchLayout;
    private ListAdapter mAdapter;
    private Context mContext;
    private List<TLRPC.User> mSearchResultList;
    private int myQRCode;
    private int offset;
    private int phoneBook;

    @BindView(R.attr.rcvList)
    RecyclerListView rcvList;
    private int reqId;
    private int rowCount;

    @BindView(R.attr.searchLayout)
    FrameLayout searchLayout;

    @BindView(R.attr.searchView)
    MrySearchView searchView;
    private boolean searching;

    @BindView(R.attr.tvSearchHeader)
    TextView tvSearchHeader;

    @BindView(R.attr.tvSearchNumber)
    TextView tvSearchNumber;

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public boolean onFragmentCreate() {
        super.onFragmentCreate();
        this.offset = -1;
        this.myQRCode = -1;
        int i = this.rowCount;
        int i2 = i + 1;
        this.rowCount = i2;
        this.codeScan = i;
        this.phoneBook = -1;
        this.rowCount = i2 + 1;
        this.inviteMore = i2;
        this.lastSectionRow = -1;
        return true;
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseSearchViewFragment, im.uwrkaxlmjj.ui.actionbar.BaseFragment
    public View createView(Context context) {
        this.mContext = context;
        this.fragmentView = LayoutInflater.from(context).inflate(R.layout.activity_add_contacts, (ViewGroup) null, false);
        this.fragmentView.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundGray));
        useButterKnife();
        initActionBar();
        initView();
        initList();
        super.createView(context);
        return this.fragmentView;
    }

    private void initActionBar() {
        this.actionBar.setTitle(LocaleController.getString("AddFriends", R.string.AddFriends));
        this.actionBar.setBackButtonImage(R.id.ic_back);
        this.actionBar.setCastShadows(false);
        this.actionBar.setActionBarMenuOnItemClick(new ActionBar.ActionBarMenuOnItemClick() { // from class: im.uwrkaxlmjj.ui.hui.contacts.AddContactsActivity.1
            @Override // im.uwrkaxlmjj.ui.actionbar.ActionBar.ActionBarMenuOnItemClick
            public void onItemClick(int id) {
                if (id == -1) {
                    AddContactsActivity.this.finishFragment();
                }
            }
        });
    }

    private void initView() {
        this.llSearchLayout.setVisibility(8);
        this.llSearchLayout.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.hui.contacts.-$$Lambda$AddContactsActivity$PVs3iMrlpb0MRr9gptJhwesYuaw
            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                this.f$0.lambda$initView$0$AddContactsActivity(view);
            }
        });
        this.tvSearchHeader.setText(LocaleController.getString("SearchHint", R.string.SearchHint));
        this.tvSearchNumber.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteBlueText));
    }

    public /* synthetic */ void lambda$initView$0$AddContactsActivity(View v) {
        searchUser(this.tvSearchNumber.getText().toString());
    }

    private void initList() {
        RecyclerListView recyclerListView = (RecyclerListView) this.fragmentView.findViewById(R.attr.rcvList);
        this.rcvList = recyclerListView;
        recyclerListView.setHasFixedSize(true);
        this.rcvList.setNestedScrollingEnabled(false);
        this.rcvList.setVerticalScrollBarEnabled(false);
        this.rcvList.setLayoutManager(new LinearLayoutManager(this.mContext, 1, false));
        ListAdapter listAdapter = new ListAdapter();
        this.mAdapter = listAdapter;
        this.rcvList.setAdapter(listAdapter);
        this.rcvList.setOnItemClickListener(new RecyclerListView.OnItemClickListener() { // from class: im.uwrkaxlmjj.ui.hui.contacts.-$$Lambda$AddContactsActivity$w208DAWRHriU8PCWMSW0As6tIC0
            @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.OnItemClickListener
            public final void onItemClick(View view, int i) {
                this.f$0.lambda$initList$1$AddContactsActivity(view, i);
            }
        });
    }

    public /* synthetic */ void lambda$initList$1$AddContactsActivity(View view, int position) {
        TLRPC.User user;
        if (this.mAdapter.mType == 0) {
            if (position == this.myQRCode) {
                QrCodeActivity qrCodeActivity = new QrCodeActivity(getUserConfig().getClientUserId());
                presentFragment(qrCodeActivity);
                return;
            }
            if (position == this.codeScan) {
                presentFragment(new QrScanActivity(), false, true);
                return;
            }
            if (position == this.phoneBook) {
                presentFragment(new PhonebookUsersActivity());
                return;
            }
            if (position == this.inviteMore) {
                try {
                    Intent intent = new Intent("android.intent.action.SEND");
                    intent.setType("text/plain");
                    String text = ContactsController.getInstance(this.currentAccount).getInviteText(0);
                    intent.putExtra("android.intent.extra.TEXT", text);
                    getParentActivity().startActivityForResult(Intent.createChooser(intent, text), SlidingItemMenuRecyclerView.DEFAULT_ITEM_SCROLL_DURATION);
                    return;
                } catch (Exception e) {
                    FileLog.e(e);
                    return;
                }
            }
            return;
        }
        if (this.mAdapter.mType == 1 && (user = this.mSearchResultList.get(position)) != null) {
            MrySearchView mrySearchView = this.searchView;
            if (mrySearchView != null && mrySearchView.isSearchFieldVisible()) {
                this.searchView.closeSearchField(false);
            }
            if (user.self || user.contact) {
                Bundle bundle = new Bundle();
                bundle.putInt("user_id", user.id);
                presentFragment(new NewProfileActivity(bundle), true);
            } else {
                Bundle bundle2 = new Bundle();
                bundle2.putInt("from_type", this.from_type);
                presentFragment(new AddContactsInfoActivity(bundle2, user), true);
            }
        }
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseSearchViewFragment
    protected MrySearchView getSearchView() {
        this.searchLayout.setBackgroundColor(Theme.getColor(Theme.key_searchview_solidColor));
        this.searchView.setEditTextBackground(getParentActivity().getDrawable(R.drawable.shape_edit_bg));
        this.searchView.setHintText(LocaleController.getString("UserNameOrPhoneNumberSearch", R.string.UserNameOrPhoneNumberSearch));
        return this.searchView;
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseSearchViewFragment, im.uwrkaxlmjj.ui.hviews.search.MrySearchView.ISearchViewDelegate
    public void onSearchExpand() {
        this.searching = true;
        setAdapterViewType(1);
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseSearchViewFragment, im.uwrkaxlmjj.ui.hviews.search.MrySearchView.ISearchViewDelegate
    public boolean canCollapseSearch() {
        return true;
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseSearchViewFragment, im.uwrkaxlmjj.ui.hviews.search.MrySearchView.ISearchViewDelegate
    public void onSearchCollapse() {
        this.searching = false;
        this.mSearchResultList = null;
        cancelRequest();
        setAdapterViewType(0);
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseSearchViewFragment, im.uwrkaxlmjj.ui.hviews.search.MrySearchView.ISearchViewDelegate
    public void onTextChange(String text) {
        this.llSearchLayout.setVisibility(text.length() > 0 ? 0 : 8);
        if (text.length() > 0) {
            this.tvSearchNumber.setText(text);
            this.llSearchLayout.setEnabled(text.length() > 0);
            this.mSearchResultList = null;
            setAdapterViewType(1);
            return;
        }
        this.mSearchResultList = null;
        setAdapterViewType(1);
    }

    @Override // im.uwrkaxlmjj.ui.actionbar.BaseSearchViewFragment, im.uwrkaxlmjj.ui.hviews.search.MrySearchView.ISearchViewDelegate
    public void onActionSearch(String trim) {
        AndroidUtilities.hideKeyboard(this.fragmentView);
    }

    private void searchUser(final String inputText) {
        TLRPCContacts.SearchUserByPhone req = new TLRPCContacts.SearchUserByPhone();
        req.phone = inputText;
        cancelRequest();
        setAdapterViewType(3);
        ConnectionsManager connectionsManager = getConnectionsManager();
        int iSendRequest = getConnectionsManager().sendRequest(req, new RequestDelegate() { // from class: im.uwrkaxlmjj.ui.hui.contacts.-$$Lambda$AddContactsActivity$RXF8032V9_LAVmHPe-Dd8mgxNYs
            @Override // im.uwrkaxlmjj.tgnet.RequestDelegate
            public final void run(TLObject tLObject, TLRPC.TL_error tL_error) {
                this.f$0.lambda$searchUser$3$AddContactsActivity(inputText, tLObject, tL_error);
            }
        });
        this.reqId = iSendRequest;
        connectionsManager.bindRequestToGuid(iSendRequest, this.classGuid);
    }

    public /* synthetic */ void lambda$searchUser$3$AddContactsActivity(final String inputText, final TLObject response, final TLRPC.TL_error error) {
        AndroidUtilities.runOnUIThread(new Runnable() { // from class: im.uwrkaxlmjj.ui.hui.contacts.-$$Lambda$AddContactsActivity$Dg3oql4Wq8GNcLawSYGR3y8Tg6g
            @Override // java.lang.Runnable
            public final void run() {
                this.f$0.lambda$null$2$AddContactsActivity(error, response, inputText);
            }
        });
    }

    public /* synthetic */ void lambda$null$2$AddContactsActivity(TLRPC.TL_error error, TLObject response, String inputText) {
        this.reqId = 0;
        this.llSearchLayout.setVisibility(8);
        if (error != null) {
            if (!TextUtils.isEmpty(error.text)) {
                setAdapterViewType(4, WalletErrorUtil.getErrorDescription(error.text));
                WalletDialog dialog = new WalletDialog(getParentActivity());
                dialog.setMessage(WalletErrorUtil.getErrorDescription(error.text));
                dialog.setPositiveButton(LocaleController.getString("confirm", R.string.confirm), null);
                showDialog(dialog);
                return;
            }
            return;
        }
        if ((response instanceof TLRPC.TL_contacts_found) && !getParentActivity().isFinishing()) {
            TLRPC.TL_contacts_found contactsFound = (TLRPC.TL_contacts_found) response;
            ArrayList<TLRPC.User> arrayList = contactsFound.users;
            this.mSearchResultList = arrayList;
            if (arrayList != null && this.mAdapter != null) {
                if (arrayList.size() == 0) {
                    setAdapterViewType(2);
                    WalletDialog dialog2 = new WalletDialog(getParentActivity());
                    dialog2.setMessage(LocaleController.getString("UserNotExist", R.string.UserNotExist));
                    dialog2.setPositiveButton(LocaleController.getString("confirm", R.string.confirm), null);
                    showDialog(dialog2);
                    return;
                }
                if (this.mSearchResultList.size() > 1) {
                    this.mSearchResultList = this.mSearchResultList.subList(0, 1);
                }
                setAdapterViewType(1);
                if (RegexUtils.isMobileSimple(inputText)) {
                    this.from_type = 3;
                } else {
                    this.from_type = 4;
                }
            }
        }
    }

    private void cancelRequest() {
        if (this.reqId != 0) {
            getConnectionsManager().cancelRequest(this.reqId, true);
            this.reqId = 0;
        }
    }

    private void setAdapterViewType(int viewType) {
        setAdapterViewType(viewType, null);
    }

    private void setAdapterViewType(int viewType, String errorText) {
        ListAdapter listAdapter = this.mAdapter;
        if (listAdapter == null) {
            return;
        }
        if (listAdapter.mType != viewType) {
            this.mAdapter.setType(viewType);
            this.mAdapter.setErrorText(errorText);
            this.mAdapter.notifyDataSetChanged();
        } else if (viewType == 4 && errorText != null && !errorText.equals(this.mAdapter.mErrorText)) {
            this.mAdapter.setErrorText(errorText);
            this.mAdapter.notifyDataSetChanged();
        } else if (this.mAdapter.mType != 3) {
            this.mAdapter.notifyDataSetChanged();
        }
    }

    private class ListAdapter extends RecyclerListView.SelectionAdapter {
        private String mErrorText;
        private int mType = 0;

        public ListAdapter() {
        }

        public void setErrorText(String errorText) {
            this.mErrorText = errorText;
        }

        public void setType(int type) {
            this.mType = type;
            if (type != 4) {
                this.mErrorText = null;
            }
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public int getItemCount() {
            int i = this.mType;
            if (i == 1) {
                if (AddContactsActivity.this.mSearchResultList != null) {
                    return AddContactsActivity.this.mSearchResultList.size();
                }
                return 0;
            }
            if (i == 2 || i == 3) {
                return 1;
            }
            return AddContactsActivity.this.rowCount;
        }

        @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.SelectionAdapter
        public boolean isEnabled(RecyclerView.ViewHolder holder) {
            int viewType = holder.getItemViewType();
            return (viewType == 2 || viewType == 3 || viewType == 4) ? false : true;
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public void onBindViewHolder(RecyclerView.ViewHolder holder, int position) {
            String userName;
            int viewType = holder.getItemViewType();
            if (viewType == 0) {
                ImageView itemImage = (ImageView) holder.itemView.findViewById(R.attr.itemImage);
                TextView itemTitle = (TextView) holder.itemView.findViewById(R.attr.itemTitle);
                TextView itemSubTitle = (TextView) holder.itemView.findViewById(R.attr.itemSubTitle);
                View vDivider = holder.itemView.findViewById(R.attr.vDivider);
                itemTitle.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteBlackText));
                itemSubTitle.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteGrayText3));
                vDivider.setBackgroundColor(Theme.getColor(Theme.key_divider));
                if (position != AddContactsActivity.this.myQRCode) {
                    if (position != AddContactsActivity.this.codeScan) {
                        if (position != AddContactsActivity.this.phoneBook) {
                            if (position == AddContactsActivity.this.inviteMore) {
                                itemImage.setImageResource(R.id.icon_invite_more);
                                itemTitle.setText(LocaleController.getString("InviteMore", R.string.InviteMore));
                                itemSubTitle.setText(LocaleController.getString("InviteApps", R.string.InviteApps));
                            }
                        } else {
                            itemImage.setImageResource(R.id.icon_mail_list);
                            itemTitle.setText(LocaleController.getString("AppContacts", R.string.AppContacts));
                            itemSubTitle.setText(LocaleController.getString("AddContactsFriend", R.string.AddContactsFriend));
                        }
                    } else {
                        itemImage.setImageResource(R.id.icon_qr_scan);
                        itemTitle.setText(LocaleController.getString("Scan", R.string.Scan));
                        itemSubTitle.setText(LocaleController.getString("QRCodeScanToAdd", R.string.QRCodeScanToAdd));
                    }
                } else {
                    itemImage.setImageResource(R.id.icon_my_qr_code);
                    itemTitle.setText(LocaleController.getString("MyQRCode", R.string.MyQRCode));
                    itemSubTitle.setText(LocaleController.getString("ShareToAdd", R.string.ShareToAdd));
                }
                if (position == getItemCount() - 1) {
                    vDivider.setVisibility(8);
                    holder.itemView.setBackground(Theme.createRoundRectDrawable(0.0f, 0.0f, AndroidUtilities.dp(5.0f), AndroidUtilities.dp(5.0f), Theme.getColor(Theme.key_windowBackgroundWhite)));
                    return;
                } else {
                    if (position == 0) {
                        holder.itemView.setBackground(Theme.createRoundRectDrawable(AndroidUtilities.dp(5.0f), AndroidUtilities.dp(5.0f), 0.0f, 0.0f, Theme.getColor(Theme.key_windowBackgroundWhite)));
                        return;
                    }
                    return;
                }
            }
            if (viewType == 1) {
                BackupImageView itemImage2 = (BackupImageView) holder.itemView.findViewById(R.attr.itemImage);
                TextView itemTitle2 = (TextView) holder.itemView.findViewById(R.attr.itemTitle);
                TextView itemSubTitle2 = (TextView) holder.itemView.findViewById(R.attr.itemSubTitle);
                View vDivider2 = holder.itemView.findViewById(R.attr.vDivider);
                itemTitle2.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteBlackText));
                itemSubTitle2.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteGrayText));
                vDivider2.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundGray));
                if (AddContactsActivity.this.mSearchResultList != null && position < AddContactsActivity.this.mSearchResultList.size()) {
                    TLRPC.User user = (TLRPC.User) AddContactsActivity.this.mSearchResultList.get(position);
                    if (user != null) {
                        AvatarDrawable avatarDrawable = new AvatarDrawable();
                        avatarDrawable.setTextSize(AndroidUtilities.dp(16.0f));
                        avatarDrawable.setInfo(user);
                        itemImage2.setRoundRadius(AndroidUtilities.dp(7.5f));
                        itemImage2.setImage(ImageLocation.getForUser(user, false), "34_34", avatarDrawable, user);
                        if (user.first_name != null) {
                            userName = user.first_name;
                        } else {
                            String userName2 = user.last_name;
                            if (userName2 != null) {
                                userName = user.last_name;
                            } else {
                                userName = LocaleController.getString("NumberUnknown", R.string.NumberUnknown);
                            }
                        }
                        itemTitle2.setText(userName);
                        itemSubTitle2.setText(LocaleController.formatUserStatus(AddContactsActivity.this.currentAccount, user));
                    }
                } else {
                    itemImage2.setImageResource(R.drawable.round_grey);
                }
                if (position == getItemCount() - 1) {
                    vDivider2.setVisibility(8);
                    return;
                }
                return;
            }
            if (viewType == 2 || viewType == 4) {
                ImageView iv = (ImageView) holder.itemView.findViewById(AddContactsActivity.ID_EMPTY_IMAGE_VIEW);
                TextView tv = (TextView) holder.itemView.findViewById(AddContactsActivity.ID_EMPTY_TEXT_VIEW);
                iv.setImageResource(0);
                tv.setText((CharSequence) null);
            }
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public RecyclerView.ViewHolder onCreateViewHolder(ViewGroup parent, int viewType) {
            View view = null;
            if (viewType == 0) {
                view = LayoutInflater.from(AddContactsActivity.this.mContext).inflate(R.layout.item_add_contacts_layout, (ViewGroup) null, false);
                view.setLayoutParams(new RecyclerView.LayoutParams(-1, AndroidUtilities.dp(65.0f)));
                view.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
            } else if (viewType == 1) {
                view = LayoutInflater.from(AddContactsActivity.this.mContext).inflate(R.layout.item_add_contacts_search_result_layout, (ViewGroup) null, false);
                view.setLayoutParams(new RecyclerView.LayoutParams(-1, AndroidUtilities.dp(65.0f)));
                view.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
            } else if (viewType == 2 || viewType == 4) {
                view = new FrameLayout(AddContactsActivity.this.mContext);
                LinearLayout ll = new LinearLayout(AddContactsActivity.this.mContext);
                ll.setOrientation(1);
                ll.setGravity(17);
                ImageView iv = new ImageView(AddContactsActivity.this.mContext);
                iv.setId(AddContactsActivity.ID_EMPTY_IMAGE_VIEW);
                ll.addView(iv, LayoutHelper.createLinear(167, 104, 17, 0, 0, 0, 8));
                TextView tv = new TextView(AddContactsActivity.this.mContext);
                tv.setId(AddContactsActivity.ID_EMPTY_TEXT_VIEW);
                tv.setTextColor(Theme.getColor(Theme.key_windowBackgroundWhiteGrayText4));
                tv.setTextSize(2, 14.0f);
                ll.addView(tv, LayoutHelper.createLinear(-2, -2, 17, 0, 8, 0, 0));
                view.setLayoutParams(new RecyclerView.LayoutParams(-1, -1));
                ((FrameLayout) view).addView(ll, LayoutHelper.createFrame(-2, -2, 17));
            } else if (viewType == 3) {
                view = new FrameLayout(AddContactsActivity.this.mContext);
                ProgressBar progressBar = new ProgressBar(AddContactsActivity.this.mContext);
                ColorStateList colorStateList = ColorStateList.valueOf(Theme.getColor(Theme.key_actionBarTabActiveText));
                if (Build.VERSION.SDK_INT >= 21) {
                    progressBar.setIndeterminateTintList(colorStateList);
                    progressBar.setIndeterminateTintMode(PorterDuff.Mode.MULTIPLY);
                } else {
                    progressBar.setIndeterminate(true);
                }
                ((FrameLayout) view).addView(progressBar, LayoutHelper.createFrame(40, 40, 17));
                view.setLayoutParams(new RecyclerView.LayoutParams(-1, -1));
                view.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
            }
            return new RecyclerListView.Holder(view);
        }

        @Override // androidx.recyclerview.widget.RecyclerView.Adapter
        public int getItemViewType(int position) {
            return this.mType;
        }
    }

    private boolean checkSearchByAccountName(String inputText) {
        return (!inputText.matches("^\\w{5,32}$") || inputText.matches("(^_|^\\d|_$|__)") || inputText.contains("3549")) ? false : true;
    }
}
