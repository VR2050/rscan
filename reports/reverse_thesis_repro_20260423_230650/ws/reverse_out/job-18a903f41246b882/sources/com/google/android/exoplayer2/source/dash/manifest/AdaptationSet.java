package com.google.android.exoplayer2.source.dash.manifest;

import java.util.Collections;
import java.util.List;

/* JADX INFO: loaded from: classes2.dex */
public class AdaptationSet {
    public static final int ID_UNSET = -1;
    public final List<Descriptor> accessibilityDescriptors;
    public final int id;
    public final List<Representation> representations;
    public final List<Descriptor> supplementalProperties;
    public final int type;

    public AdaptationSet(int id, int type, List<Representation> representations, List<Descriptor> accessibilityDescriptors, List<Descriptor> supplementalProperties) {
        List<Descriptor> listUnmodifiableList;
        List<Descriptor> listUnmodifiableList2;
        this.id = id;
        this.type = type;
        this.representations = Collections.unmodifiableList(representations);
        if (accessibilityDescriptors == null) {
            listUnmodifiableList = Collections.emptyList();
        } else {
            listUnmodifiableList = Collections.unmodifiableList(accessibilityDescriptors);
        }
        this.accessibilityDescriptors = listUnmodifiableList;
        if (supplementalProperties == null) {
            listUnmodifiableList2 = Collections.emptyList();
        } else {
            listUnmodifiableList2 = Collections.unmodifiableList(supplementalProperties);
        }
        this.supplementalProperties = listUnmodifiableList2;
    }
}
