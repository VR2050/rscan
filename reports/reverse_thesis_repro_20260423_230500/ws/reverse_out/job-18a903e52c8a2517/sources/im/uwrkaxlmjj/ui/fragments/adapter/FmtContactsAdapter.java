package im.uwrkaxlmjj.ui.fragments.adapter;

import android.content.Context;
import android.util.SparseArray;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageView;
import android.widget.LinearLayout;
import androidx.recyclerview.widget.RecyclerView;
import im.uwrkaxlmjj.messenger.AndroidUtilities;
import im.uwrkaxlmjj.messenger.ContactsController;
import im.uwrkaxlmjj.messenger.FileLog;
import im.uwrkaxlmjj.messenger.LocaleController;
import im.uwrkaxlmjj.messenger.MessagesController;
import im.uwrkaxlmjj.messenger.UserConfig;
import im.uwrkaxlmjj.tgnet.ConnectionsManager;
import im.uwrkaxlmjj.tgnet.TLRPC;
import im.uwrkaxlmjj.ui.actionbar.Theme;
import im.uwrkaxlmjj.ui.cells.EmptyCell;
import im.uwrkaxlmjj.ui.cells.LetterSectionCell;
import im.uwrkaxlmjj.ui.components.RecyclerListView;
import im.uwrkaxlmjj.ui.hcells.ContactUserCell;
import im.uwrkaxlmjj.ui.hviews.MryTextView;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import mpEIGo.juqQQs.esbSDO.R;

/* JADX INFO: loaded from: classes5.dex */
public class FmtContactsAdapter extends RecyclerListView.SectionsAdapter {
    private SparseArray<?> checkedMap;
    private int classGuid;
    private FmtContactsAdapterDelegate delegate;
    private boolean disableSections;
    private boolean hasGps;
    private OnContactHeaderItemClickListener headerListener;
    private SparseArray<TLRPC.User> ignoreUsers;
    private boolean isAdmin;
    private boolean isChannel;
    private Context mContext;
    private boolean needPhonebook;
    private ArrayList<TLRPC.Contact> onlineContacts;
    private int onlyUsers;
    private boolean scrolling;
    private int sortType;
    private int currentAccount = UserConfig.selectedAccount;
    private HashMap<Integer, Integer> userPositionMap = new HashMap<>();

    public interface FmtContactsAdapterDelegate {
        void onDeleteItem(int i);
    }

    public interface OnContactHeaderItemClickListener {
        void onItemClick(View view);
    }

    public FmtContactsAdapter(Context mContext, int onlyUsersType, boolean needPhonebook, SparseArray<TLRPC.User> ignores, int flags, boolean hasGps) {
        this.mContext = mContext;
        this.onlyUsers = onlyUsersType;
        this.needPhonebook = needPhonebook;
        this.ignoreUsers = ignores;
        this.isAdmin = flags != 0;
        this.isChannel = flags == 2;
        this.hasGps = hasGps;
    }

    public void setDisableSections(boolean value) {
        this.disableSections = value;
    }

    public void setSortType(int value) {
        this.sortType = value;
        if (value == 2) {
            if (this.onlineContacts == null) {
                this.onlineContacts = new ArrayList<>(ContactsController.getInstance(this.currentAccount).contacts);
                int selfId = UserConfig.getInstance(this.currentAccount).clientUserId;
                int i = 0;
                int len = this.onlineContacts.size();
                while (true) {
                    if (i >= len) {
                        break;
                    }
                    if (this.onlineContacts.get(i).user_id != selfId) {
                        i++;
                    } else {
                        this.onlineContacts.remove(i);
                        break;
                    }
                }
            }
            sortOnlineContacts();
            return;
        }
        notifyDataSetChanged();
    }

    public int getSectionForChar(char section) {
        ArrayList<String> sortedUsersSectionsArray = ContactsController.getInstance(this.currentAccount).sortedUsersSectionsArray;
        for (int i = 0; i < getSectionCount() - 1; i++) {
            String sortStr = sortedUsersSectionsArray.get(i);
            char firstChar = sortStr.toUpperCase().charAt(0);
            if (firstChar == section) {
                return i + 1;
            }
        }
        return -1;
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

    public void sortOnlineContacts() {
        if (this.onlineContacts == null) {
            return;
        }
        try {
            final int currentTime = ConnectionsManager.getInstance(this.currentAccount).getCurrentTime();
            final MessagesController messagesController = MessagesController.getInstance(this.currentAccount);
            Collections.sort(this.onlineContacts, new Comparator() { // from class: im.uwrkaxlmjj.ui.fragments.adapter.-$$Lambda$FmtContactsAdapter$eTczY7sGFt6iJpWPspUn8AVCHak
                @Override // java.util.Comparator
                public final int compare(Object obj, Object obj2) {
                    return FmtContactsAdapter.lambda$sortOnlineContacts$0(messagesController, currentTime, (TLRPC.Contact) obj, (TLRPC.Contact) obj2);
                }
            });
            notifyDataSetChanged();
        } catch (Exception e) {
            FileLog.e(e);
        }
    }

    static /* synthetic */ int lambda$sortOnlineContacts$0(MessagesController messagesController, int currentTime, TLRPC.Contact objPre, TLRPC.Contact objNext) {
        TLRPC.User userPre = messagesController.getUser(Integer.valueOf(objPre.user_id));
        TLRPC.User userNext = messagesController.getUser(Integer.valueOf(objNext.user_id));
        int status1 = 0;
        int status2 = 0;
        if (userPre != null) {
            if (userPre.self) {
                status1 = currentTime + 50000;
            } else if (userPre.status != null) {
                status1 = userPre.status.expires;
            }
        }
        if (userNext != null) {
            if (userNext.self) {
                status2 = currentTime + 50000;
            } else if (userNext.status != null) {
                status2 = userNext.status.expires;
            }
        }
        if (status1 > 0 && status2 > 0) {
            if (status1 > status2) {
                return 1;
            }
            return status1 < status2 ? -1 : 0;
        }
        if (status1 < 0 && status2 < 0) {
            if (status1 > status2) {
                return 1;
            }
            return status1 < status2 ? -1 : 0;
        }
        if ((status1 >= 0 || status2 <= 0) && (status1 != 0 || status2 == 0)) {
            return ((status2 >= 0 || status1 <= 0) && (status2 != 0 || status1 == 0)) ? 0 : 1;
        }
        return -1;
    }

    @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.SectionsAdapter
    public Object getItem(int section, int position) {
        HashMap<String, ArrayList<TLRPC.Contact>> usersSectionsDict = this.onlyUsers == 2 ? ContactsController.getInstance(this.currentAccount).usersMutualSectionsDict : ContactsController.getInstance(this.currentAccount).usersSectionsDict;
        ArrayList<String> sortedUsersSectionsArray = this.onlyUsers == 2 ? ContactsController.getInstance(this.currentAccount).sortedUsersMutualSectionsArray : ContactsController.getInstance(this.currentAccount).sortedUsersSectionsArray;
        if (this.onlyUsers != 0 && !this.isAdmin) {
            if (section < sortedUsersSectionsArray.size()) {
                ArrayList<TLRPC.Contact> arr = usersSectionsDict.get(sortedUsersSectionsArray.get(section));
                if (position < arr.size()) {
                    return MessagesController.getInstance(this.currentAccount).getUser(Integer.valueOf(arr.get(position).user_id));
                }
            }
            return null;
        }
        if (section == 0) {
            return null;
        }
        if (this.sortType == 2) {
            if (section == 1) {
                if (position < this.onlineContacts.size()) {
                    return MessagesController.getInstance(this.currentAccount).getUser(Integer.valueOf(this.onlineContacts.get(position).user_id));
                }
                return null;
            }
        } else if (section - 1 < sortedUsersSectionsArray.size()) {
            ArrayList<TLRPC.Contact> arr2 = usersSectionsDict.get(sortedUsersSectionsArray.get(section - 1));
            if (position < arr2.size()) {
                return MessagesController.getInstance(this.currentAccount).getUser(Integer.valueOf(arr2.get(position).user_id));
            }
            return null;
        }
        if (this.needPhonebook) {
            return ContactsController.getInstance(this.currentAccount).phoneBookContacts.get(position);
        }
        return null;
    }

    @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.FastScrollAdapter
    public String getLetter(int position) {
        if (this.sortType == 2) {
            return null;
        }
        ArrayList<String> sortedUsersSectionsArray = this.onlyUsers == 2 ? ContactsController.getInstance(this.currentAccount).sortedUsersMutualSectionsArray : ContactsController.getInstance(this.currentAccount).sortedUsersSectionsArray;
        int section = getSectionForPosition(position);
        if (section == -1) {
            section = sortedUsersSectionsArray.size() - 1;
        }
        if (this.onlyUsers != 0 && !this.isAdmin) {
            if (section >= 0 && section < sortedUsersSectionsArray.size()) {
                return sortedUsersSectionsArray.get(section);
            }
        } else if (section > 0 && section <= sortedUsersSectionsArray.size()) {
            return sortedUsersSectionsArray.get(section - 1);
        }
        return null;
    }

    @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.FastScrollAdapter
    public int getPositionForScrollProgress(float progress) {
        return (int) (getItemCount() * progress);
    }

    @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.SectionsAdapter
    public int getSectionCount() {
        ArrayList<String> sortedUsersSectionsArray = this.onlyUsers == 2 ? ContactsController.getInstance(this.currentAccount).sortedUsersMutualSectionsArray : ContactsController.getInstance(this.currentAccount).sortedUsersSectionsArray;
        int count = sortedUsersSectionsArray.size();
        if (this.onlyUsers == 0) {
            count++;
        }
        if (this.isAdmin) {
            return count + 1;
        }
        return count;
    }

    @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.SectionsAdapter
    public int getCountForSection(int section) {
        ArrayList<TLRPC.Contact> arr;
        HashMap<String, ArrayList<TLRPC.Contact>> usersSectionsDict = this.onlyUsers == 2 ? ContactsController.getInstance(this.currentAccount).usersMutualSectionsDict : ContactsController.getInstance(this.currentAccount).usersSectionsDict;
        ArrayList<String> sortedUsersSectionsArray = this.onlyUsers == 2 ? ContactsController.getInstance(this.currentAccount).sortedUsersMutualSectionsArray : ContactsController.getInstance(this.currentAccount).sortedUsersSectionsArray;
        if (section == 0) {
            return 2;
        }
        if (section - 1 < sortedUsersSectionsArray.size() && (arr = usersSectionsDict.get(sortedUsersSectionsArray.get(section - 1))) != null) {
            int count = arr.size();
            if (section - 1 == sortedUsersSectionsArray.size() - 1) {
                return count + 1;
            }
            return count;
        }
        if (this.needPhonebook) {
            return ContactsController.getInstance(this.currentAccount).phoneBookContacts.size();
        }
        return 0;
    }

    @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.SectionsAdapter
    public boolean isEnabled(int section, int row) {
        HashMap<String, ArrayList<TLRPC.Contact>> usersSectionsDict = this.onlyUsers == 2 ? ContactsController.getInstance(this.currentAccount).usersMutualSectionsDict : ContactsController.getInstance(this.currentAccount).usersSectionsDict;
        ArrayList<String> sortedUsersSectionsArray = this.onlyUsers == 2 ? ContactsController.getInstance(this.currentAccount).sortedUsersMutualSectionsArray : ContactsController.getInstance(this.currentAccount).sortedUsersSectionsArray;
        if (this.onlyUsers != 0 && !this.isAdmin) {
            ArrayList<TLRPC.Contact> arr = usersSectionsDict.get(sortedUsersSectionsArray.get(section));
            return row < arr.size();
        }
        if (section == 0) {
            return false;
        }
        if (this.sortType == 2) {
            return section != 1 || row < this.onlineContacts.size();
        }
        if (section - 1 < sortedUsersSectionsArray.size()) {
            ArrayList<TLRPC.Contact> arr2 = usersSectionsDict.get(sortedUsersSectionsArray.get(section - 1));
            return row < arr2.size();
        }
        return true;
    }

    @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.SectionsAdapter
    public int getItemViewType(int section, int position) {
        HashMap<String, ArrayList<TLRPC.Contact>> usersSectionsDict = this.onlyUsers == 2 ? ContactsController.getInstance(this.currentAccount).usersMutualSectionsDict : ContactsController.getInstance(this.currentAccount).usersSectionsDict;
        ArrayList<String> sortedUsersSectionsArray = this.onlyUsers == 2 ? ContactsController.getInstance(this.currentAccount).sortedUsersMutualSectionsArray : ContactsController.getInstance(this.currentAccount).sortedUsersSectionsArray;
        if (section == 0) {
            return position == 0 ? 1 : 2;
        }
        if (section - 1 >= sortedUsersSectionsArray.size()) {
            return 1;
        }
        ArrayList<TLRPC.Contact> arr = usersSectionsDict.get(sortedUsersSectionsArray.get(section - 1));
        return section + (-1) == sortedUsersSectionsArray.size() - 1 ? position < arr.size() ? 0 : 5 : position < arr.size() ? 0 : 4;
    }

    @Override // androidx.recyclerview.widget.RecyclerView.Adapter
    public RecyclerView.ViewHolder onCreateViewHolder(ViewGroup parent, int viewType) {
        View view;
        if (viewType == 0) {
            View view2 = LayoutInflater.from(this.mContext).inflate(R.layout.item_contacts_layout, (ViewGroup) null);
            view2.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundWhite));
            view = view2;
        } else if (viewType == 1) {
            View view3 = LayoutInflater.from(this.mContext).inflate(R.layout.item_contacts_header, parent, false);
            view3.setMinimumHeight(AndroidUtilities.dp(105.0f));
            view3.setBackground(Theme.createRoundRectDrawable(AndroidUtilities.dp(5.0f), AndroidUtilities.dp(5.0f), 0.0f, 0.0f, Theme.getColor(Theme.key_windowBackgroundWhite)));
            view = view3;
        } else if (viewType == 2) {
            view = new EmptyCell(this.mContext, AndroidUtilities.dp(10.0f));
            view.setBackgroundColor(Theme.getColor(Theme.key_windowBackgroundGray));
        } else if (viewType == 3) {
            view = new EmptyCell(this.mContext, AndroidUtilities.dp(46.0f));
            view.setBackgroundColor(16776960);
        } else if (viewType == 5) {
            view = new MryTextView(this.mContext);
            view.setBackgroundColor(0);
            view.setMinimumHeight(AndroidUtilities.dp(70.0f));
            ((MryTextView) view).setGravity(17);
            ((MryTextView) view).setTextSize(13.0f);
        } else {
            view = new View(this.mContext);
            view.setBackgroundColor(16760097);
            view.setMinimumHeight(AndroidUtilities.dp(48.0f));
            view.setPadding(AndroidUtilities.dp(LocaleController.isRTL ? 28.0f : 72.0f), AndroidUtilities.dp(8.0f), AndroidUtilities.dp(LocaleController.isRTL ? 72.0f : 28.0f), AndroidUtilities.dp(8.0f));
        }
        view.setLayoutParams(new RecyclerView.LayoutParams(-1, -2));
        return new RecyclerListView.Holder(view);
    }

    @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.SectionsAdapter
    public void onBindViewHolder(int i, int i2, RecyclerView.ViewHolder viewHolder) {
        ArrayList<TLRPC.Contact> arrayList;
        int itemViewType = viewHolder.getItemViewType();
        if (itemViewType == 0) {
            ContactUserCell contactUserCell = (ContactUserCell) viewHolder.itemView.findViewById(R.attr.contactUserCell);
            contactUserCell.setAvatarPadding((this.sortType == 2 || this.disableSections) ? 6 : 58);
            if (this.sortType == 2) {
                arrayList = this.onlineContacts;
            } else {
                arrayList = (this.onlyUsers == 2 ? ContactsController.getInstance(this.currentAccount).usersMutualSectionsDict : ContactsController.getInstance(this.currentAccount).usersSectionsDict).get((this.onlyUsers == 2 ? ContactsController.getInstance(this.currentAccount).sortedUsersMutualSectionsArray : ContactsController.getInstance(this.currentAccount).sortedUsersSectionsArray).get(i - ((this.onlyUsers == 0 || this.isAdmin) ? 1 : 0)));
            }
            TLRPC.User user = MessagesController.getInstance(this.currentAccount).getUser(Integer.valueOf(arrayList.get(i2).user_id));
            if (MessagesController.getInstance(this.currentAccount).getUserFull(user.id) == null) {
                MessagesController.getInstance(this.currentAccount).loadUserInfo(user, true, this.classGuid);
            } else {
                contactUserCell.setUserFull(MessagesController.getInstance(this.currentAccount).getUserFull(user.id));
            }
            if (i == getSectionCount() - 1 && i2 == arrayList.size() - 1) {
                contactUserCell.setData(user, null, null, 0);
                viewHolder.itemView.setBackground(Theme.createRoundRectDrawable(0.0f, 0.0f, AndroidUtilities.dp(5.0f), AndroidUtilities.dp(5.0f), Theme.getColor(Theme.key_windowBackgroundWhite)));
            } else {
                contactUserCell.setData(user, null, null, 0, true);
            }
            SparseArray<?> sparseArray = this.checkedMap;
            if (sparseArray != null) {
                contactUserCell.setChecked(sparseArray.indexOfKey(user.id) >= 0, true ^ this.scrolling);
            }
            SparseArray<TLRPC.User> sparseArray2 = this.ignoreUsers;
            if (sparseArray2 != null) {
                if (sparseArray2.indexOfKey(user.id) >= 0) {
                    contactUserCell.setAlpha(0.5f);
                } else {
                    contactUserCell.setAlpha(1.0f);
                }
            }
            this.userPositionMap.put(Integer.valueOf(user.id), Integer.valueOf(getPositionForSection(i) + i2));
            return;
        }
        if (itemViewType == 1) {
            if (i == 0 && this.needPhonebook) {
                LinearLayout linearLayout = (LinearLayout) viewHolder.itemView.findViewById(R.attr.ll_new_friend);
                LinearLayout linearLayout2 = (LinearLayout) viewHolder.itemView.findViewById(R.attr.ll_my_grouping);
                LinearLayout linearLayout3 = (LinearLayout) viewHolder.itemView.findViewById(R.attr.ll_my_group);
                LinearLayout linearLayout4 = (LinearLayout) viewHolder.itemView.findViewById(R.attr.ll_my_channel);
                ((ImageView) viewHolder.itemView.findViewById(R.attr.iv_unread)).setVisibility(MessagesController.getMainSettings(this.currentAccount).getInt("contacts_apply_count", 0) <= 0 ? 8 : 0);
                linearLayout.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.fragments.adapter.-$$Lambda$FmtContactsAdapter$XuWUb0mSYRJ8AG3hSA_aG9AV7tQ
                    @Override // android.view.View.OnClickListener
                    public final void onClick(View view) {
                        this.f$0.lambda$onBindViewHolder$1$FmtContactsAdapter(view);
                    }
                });
                linearLayout2.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.fragments.adapter.-$$Lambda$FmtContactsAdapter$wjbpZXFgdF0eEpOt00MAbLYQtm4
                    @Override // android.view.View.OnClickListener
                    public final void onClick(View view) {
                        this.f$0.lambda$onBindViewHolder$2$FmtContactsAdapter(view);
                    }
                });
                linearLayout3.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.fragments.adapter.-$$Lambda$FmtContactsAdapter$Vc7cVUfL5rYZsOUaRZQGn6yGurk
                    @Override // android.view.View.OnClickListener
                    public final void onClick(View view) {
                        this.f$0.lambda$onBindViewHolder$3$FmtContactsAdapter(view);
                    }
                });
                linearLayout4.setOnClickListener(new View.OnClickListener() { // from class: im.uwrkaxlmjj.ui.fragments.adapter.-$$Lambda$FmtContactsAdapter$NoXC10W5FiuVL5cnd-ypB8W9R3E
                    @Override // android.view.View.OnClickListener
                    public final void onClick(View view) {
                        this.f$0.lambda$onBindViewHolder$4$FmtContactsAdapter(view);
                    }
                });
                return;
            }
            return;
        }
        if (itemViewType == 5) {
            MryTextView mryTextView = (MryTextView) viewHolder.itemView;
            mryTextView.setTextColor(Theme.key_windowBackgroundWhiteGrayText8);
            HashMap<String, ArrayList<TLRPC.Contact>> map = this.onlyUsers == 2 ? ContactsController.getInstance(this.currentAccount).usersMutualSectionsDict : ContactsController.getInstance(this.currentAccount).usersSectionsDict;
            int size = 0;
            if (map != null) {
                Iterator<Map.Entry<String, ArrayList<TLRPC.Contact>>> it = map.entrySet().iterator();
                while (it.hasNext()) {
                    size += it.next().getValue().size();
                }
            }
            mryTextView.setText(size + LocaleController.getString(R.string.CountOfContractsPeople));
        }
    }

    public /* synthetic */ void lambda$onBindViewHolder$1$FmtContactsAdapter(View v) {
        OnContactHeaderItemClickListener onContactHeaderItemClickListener = this.headerListener;
        if (onContactHeaderItemClickListener != null) {
            onContactHeaderItemClickListener.onItemClick(v);
        }
    }

    public /* synthetic */ void lambda$onBindViewHolder$2$FmtContactsAdapter(View v) {
        OnContactHeaderItemClickListener onContactHeaderItemClickListener = this.headerListener;
        if (onContactHeaderItemClickListener != null) {
            onContactHeaderItemClickListener.onItemClick(v);
        }
    }

    public /* synthetic */ void lambda$onBindViewHolder$3$FmtContactsAdapter(View v) {
        OnContactHeaderItemClickListener onContactHeaderItemClickListener = this.headerListener;
        if (onContactHeaderItemClickListener != null) {
            onContactHeaderItemClickListener.onItemClick(v);
        }
    }

    public /* synthetic */ void lambda$onBindViewHolder$4$FmtContactsAdapter(View v) {
        OnContactHeaderItemClickListener onContactHeaderItemClickListener = this.headerListener;
        if (onContactHeaderItemClickListener != null) {
            onContactHeaderItemClickListener.onItemClick(v);
        }
    }

    @Override // im.uwrkaxlmjj.ui.components.RecyclerListView.SectionsAdapter
    public View getSectionHeaderView(int section, View view) {
        if (this.onlyUsers == 2) {
            HashMap<String, ArrayList<TLRPC.Contact>> map = ContactsController.getInstance(this.currentAccount).usersMutualSectionsDict;
        } else {
            HashMap<String, ArrayList<TLRPC.Contact>> map2 = ContactsController.getInstance(this.currentAccount).usersSectionsDict;
        }
        ArrayList<String> sortedUsersSectionsArray = this.onlyUsers == 2 ? ContactsController.getInstance(this.currentAccount).sortedUsersMutualSectionsArray : ContactsController.getInstance(this.currentAccount).sortedUsersSectionsArray;
        if (view == null) {
            view = new LetterSectionCell(this.mContext);
        }
        LetterSectionCell cell = (LetterSectionCell) view;
        if (this.sortType == 2 || this.disableSections) {
            cell.setLetter("");
        } else if (this.onlyUsers != 0 && !this.isAdmin) {
            if (section < sortedUsersSectionsArray.size()) {
                cell.setLetter(sortedUsersSectionsArray.get(section));
            } else {
                cell.setLetter("");
            }
        } else if (section != 0 && section - 1 < sortedUsersSectionsArray.size()) {
            cell.setLetter(sortedUsersSectionsArray.get(section - 1));
        } else {
            cell.setLetter("");
        }
        return view;
    }

    public void setDelegate(FmtContactsAdapterDelegate delegate) {
        this.delegate = delegate;
    }

    public void setOnContactHeaderItemClickListener(OnContactHeaderItemClickListener listener) {
        this.headerListener = listener;
    }

    public void setClassGuid(int classGuid) {
        this.classGuid = classGuid;
    }

    public int getItemPosition(int userId) {
        if (this.userPositionMap.get(Integer.valueOf(userId)) != null) {
            return this.userPositionMap.get(Integer.valueOf(userId)).intValue();
        }
        return -1;
    }
}
