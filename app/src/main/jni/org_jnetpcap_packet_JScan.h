/* DO NOT EDIT THIS FILE - it is machine generated */
#include <jni.h>
/* Header for class org_jnetpcap_packet_JScan */

#ifndef _Included_org_jnetpcap_packet_JScan
#define _Included_org_jnetpcap_packet_JScan
#ifdef __cplusplus
extern "C" {
#endif
/* Inaccessible static: directMemory */
/* Inaccessible static: directMemorySoft */
#undef org_jnetpcap_packet_JScan_MAX_DIRECT_MEMORY_DEFAULT
#define org_jnetpcap_packet_JScan_MAX_DIRECT_MEMORY_DEFAULT 67108864LL
/* Inaccessible static: POINTER */
#undef org_jnetpcap_packet_JScan_END_OF_HEADERS_ID
#define org_jnetpcap_packet_JScan_END_OF_HEADERS_ID -1L
/*
 * Class:     org_jnetpcap_packet_JScan
 * Method:    scan_id
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_org_jnetpcap_packet_JScan_scan_1id__
  (JNIEnv *, jobject);

/*
 * Class:     org_jnetpcap_packet_JScan
 * Method:    scan_next_id
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_org_jnetpcap_packet_JScan_scan_1next_1id__
  (JNIEnv *, jobject);

/*
 * Class:     org_jnetpcap_packet_JScan
 * Method:    scan_length
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_org_jnetpcap_packet_JScan_scan_1length__
  (JNIEnv *, jobject);

/*
 * Class:     org_jnetpcap_packet_JScan
 * Method:    scan_id
 * Signature: (I)V
 */
JNIEXPORT void JNICALL Java_org_jnetpcap_packet_JScan_scan_1id__I
  (JNIEnv *, jobject, jint);

/*
 * Class:     org_jnetpcap_packet_JScan
 * Method:    scan_next_id
 * Signature: (I)V
 */
JNIEXPORT void JNICALL Java_org_jnetpcap_packet_JScan_scan_1next_1id__I
  (JNIEnv *, jobject, jint);

/*
 * Class:     org_jnetpcap_packet_JScan
 * Method:    scan_length
 * Signature: (I)V
 */
JNIEXPORT void JNICALL Java_org_jnetpcap_packet_JScan_scan_1length__I
  (JNIEnv *, jobject, jint);

/*
 * Class:     org_jnetpcap_packet_JScan
 * Method:    scan_prefix
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_org_jnetpcap_packet_JScan_scan_1prefix__
  (JNIEnv *, jobject);

/*
 * Class:     org_jnetpcap_packet_JScan
 * Method:    scan_gap
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_org_jnetpcap_packet_JScan_scan_1gap__
  (JNIEnv *, jobject);

/*
 * Class:     org_jnetpcap_packet_JScan
 * Method:    scan_payload
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_org_jnetpcap_packet_JScan_scan_1payload__
  (JNIEnv *, jobject);

/*
 * Class:     org_jnetpcap_packet_JScan
 * Method:    scan_postix
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_org_jnetpcap_packet_JScan_scan_1postix__
  (JNIEnv *, jobject);

/*
 * Class:     org_jnetpcap_packet_JScan
 * Method:    record_header
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_org_jnetpcap_packet_JScan_record_1header__
  (JNIEnv *, jobject);

/*
 * Class:     org_jnetpcap_packet_JScan
 * Method:    scan_prefix
 * Signature: (I)V
 */
JNIEXPORT void JNICALL Java_org_jnetpcap_packet_JScan_scan_1prefix__I
  (JNIEnv *, jobject, jint);

/*
 * Class:     org_jnetpcap_packet_JScan
 * Method:    scan_gap
 * Signature: (I)V
 */
JNIEXPORT void JNICALL Java_org_jnetpcap_packet_JScan_scan_1gap__I
  (JNIEnv *, jobject, jint);

/*
 * Class:     org_jnetpcap_packet_JScan
 * Method:    scan_payload
 * Signature: (I)V
 */
JNIEXPORT void JNICALL Java_org_jnetpcap_packet_JScan_scan_1payload__I
  (JNIEnv *, jobject, jint);

/*
 * Class:     org_jnetpcap_packet_JScan
 * Method:    scan_postix
 * Signature: (I)V
 */
JNIEXPORT void JNICALL Java_org_jnetpcap_packet_JScan_scan_1postix__I
  (JNIEnv *, jobject, jint);

/*
 * Class:     org_jnetpcap_packet_JScan
 * Method:    record_header
 * Signature: (I)V
 */
JNIEXPORT void JNICALL Java_org_jnetpcap_packet_JScan_record_1header__I
  (JNIEnv *, jobject, jint);

/*
 * Class:     org_jnetpcap_packet_JScan
 * Method:    scan_set_lengths
 * Signature: (IIIII)V
 */
JNIEXPORT void JNICALL Java_org_jnetpcap_packet_JScan_scan_1set_1lengths
  (JNIEnv *, jobject, jint, jint, jint, jint, jint);

/*
 * Class:     org_jnetpcap_packet_JScan
 * Method:    sizeof
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_org_jnetpcap_packet_JScan_sizeof
  (JNIEnv *, jclass);

/*
 * Class:     org_jnetpcap_packet_JScan
 * Method:    scan_buf
 * Signature: (Lorg/jnetpcap/nio/JBuffer;)V
 */
JNIEXPORT void JNICALL Java_org_jnetpcap_packet_JScan_scan_1buf
  (JNIEnv *, jobject, jobject);

/*
 * Class:     org_jnetpcap_packet_JScan
 * Method:    scan_buf_len
 * Signature: (I)V
 */
JNIEXPORT void JNICALL Java_org_jnetpcap_packet_JScan_scan_1buf_1len
  (JNIEnv *, jobject, jint);

/*
 * Class:     org_jnetpcap_packet_JScan
 * Method:    scan_offset
 * Signature: (I)V
 */
JNIEXPORT void JNICALL Java_org_jnetpcap_packet_JScan_scan_1offset__I
  (JNIEnv *, jobject, jint);

/*
 * Class:     org_jnetpcap_packet_JScan
 * Method:    scan_packet
 * Signature: ()Lorg/jnetpcap/packet/JPacket;
 */
JNIEXPORT jobject JNICALL Java_org_jnetpcap_packet_JScan_scan_1packet
  (JNIEnv *, jobject);

/*
 * Class:     org_jnetpcap_packet_JScan
 * Method:    scan_offset
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_org_jnetpcap_packet_JScan_scan_1offset__
  (JNIEnv *, jobject);

#ifdef __cplusplus
}
#endif
#endif
