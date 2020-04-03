/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#define NEW_SIMD_CODE

#ifdef KERNEL_STATIC
#include "inc_vendor.h"
#include "inc_types.h"
#include "inc_platform.cl"
#include "inc_common.cl"
#include "inc_simd.cl"
#include "inc_hash_md5.cl"
#include "inc_cipher_aes.cl"
#endif

typedef struct
{
  u32 first_block[4];
  u32 known_header[4];
  u32 header_mask[4];
} ose_data_t;

KERNEL_FQ void m23900_init (KERN_ATTR_TMPS(void))
{
}

KERNEL_FQ void m23900_loop (KERN_ATTR_TMPS(void))
{
}

KERNEL_FQ void m23900_comp (KERN_ATTR_TMPS_ESALT(void, ose_data_t))
{
  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * aes shared
   */

  #ifdef REAL_SHM

  LOCAL_VK u32 s_td0[256];
  LOCAL_VK u32 s_td1[256];
  LOCAL_VK u32 s_td2[256];
  LOCAL_VK u32 s_td3[256];
  LOCAL_VK u32 s_td4[256];

  LOCAL_VK u32 s_te0[256];
  LOCAL_VK u32 s_te1[256];
  LOCAL_VK u32 s_te2[256];
  LOCAL_VK u32 s_te3[256];
  LOCAL_VK u32 s_te4[256];

  for (u32 i = lid; i < 256; i += lsz)
  {
    s_td0[i] = td0[i];
    s_td1[i] = td1[i];
    s_td2[i] = td2[i];
    s_td3[i] = td3[i];
    s_td4[i] = td4[i];

    s_te0[i] = te0[i];
    s_te1[i] = te1[i];
    s_te2[i] = te2[i];
    s_te3[i] = te3[i];
    s_te4[i] = te4[i];
  }

  SYNC_THREADS ();

  #else

  CONSTANT_AS u32a *s_td0 = td0;
  CONSTANT_AS u32a *s_td1 = td1;
  CONSTANT_AS u32a *s_td2 = td2;
  CONSTANT_AS u32a *s_td3 = td3;
  CONSTANT_AS u32a *s_td4 = td4;

  CONSTANT_AS u32a *s_te0 = te0;
  CONSTANT_AS u32a *s_te1 = te1;
  CONSTANT_AS u32a *s_te2 = te2;
  CONSTANT_AS u32a *s_te3 = te3;
  CONSTANT_AS u32a *s_te4 = te4;

  #endif

  if (gid >= gid_max) return;

  /**
   * copy to locals
   */

  const u32 salt[16] =
  {
    salt_bufs[salt_pos].salt_buf[0],
    salt_bufs[salt_pos].salt_buf[1]
  };

  const u32 first_block[4] =
  {
    esalt_bufs[digests_offset].first_block[0],
    esalt_bufs[digests_offset].first_block[1],
    esalt_bufs[digests_offset].first_block[2],
    esalt_bufs[digests_offset].first_block[3]
  };

  const u32 known_header[4] =
  {
    esalt_bufs[digests_offset].known_header[0],
    esalt_bufs[digests_offset].known_header[1],
    esalt_bufs[digests_offset].known_header[2],
    esalt_bufs[digests_offset].known_header[3]
  };

  const u32 header_mask[4] =
  {
    esalt_bufs[digests_offset].header_mask[0],
    esalt_bufs[digests_offset].header_mask[1],
    esalt_bufs[digests_offset].header_mask[2],
    esalt_bufs[digests_offset].header_mask[3]
  };

  /**
   * KDF
   */

  //printf ("[pure] PW:%d: %08x-%08x\n", pws[gid].pw_len, pws[gid].i[0], pws[gid].i[1]);

  // AES256 Key = H1 || H2
  u32 aes_key[8];

  // H1 = MD5(PW || SALT)
  md5_ctx_t ctx;
  md5_init (&ctx);
  md5_update_global (&ctx, pws[gid].i, pws[gid].pw_len);
  md5_update (&ctx, salt, 8);
  md5_final (&ctx);

  //printf ("H1: %08x-%08x-%08x-%08x\n", ctx.h[0], ctx.h[1], ctx.h[2], ctx.h[3] );

  aes_key[0] = ctx.h[0];
  aes_key[1] = ctx.h[1];
  aes_key[2] = ctx.h[2];
  aes_key[3] = ctx.h[3];

  u32 prev[16] = { 0 };
  prev[0] = ctx.h[0];
  prev[1] = ctx.h[1];
  prev[2] = ctx.h[2];
  prev[3] = ctx.h[3];

  //H2 = MD5(H1 || PW || SALT)
  md5_init (&ctx);
  md5_update (&ctx, prev, 16);
  md5_update_global (&ctx, pws[gid].i, pws[gid].pw_len);
  md5_update (&ctx, salt, 8);
  md5_final (&ctx);
    
  //printf ("H2: %08x-%08x-%08x-%08x\n", ctx.h[0], ctx.h[1], ctx.h[2], ctx.h[3] );
    
  aes_key[4] = ctx.h[0];
  aes_key[5] = ctx.h[1];
  aes_key[6] = ctx.h[2];
  aes_key[7] = ctx.h[3];

  prev[0] = ctx.h[0];
  prev[1] = ctx.h[1];
  prev[2] = ctx.h[2];
  prev[3] = ctx.h[3];

  //IV = MD5(H2 || PW || SALT)
  md5_init (&ctx);
  md5_update (&ctx, prev, 16);
  md5_update_global (&ctx, pws[gid].i, pws[gid].pw_len);
  md5_update (&ctx, salt, 8);
  md5_final (&ctx);

  //printf ("IV: %08x-%08x-%08x-%08x\n", ctx.h[0], ctx.h[1], ctx.h[2], ctx.h[3] );

  /**
   * AES256-CBC
   */

  u32 ks[60];
  aes256_set_decrypt_key (ks, aes_key, s_te0, s_te1, s_te2, s_te3, s_td0, s_td1, s_td2, s_td3);

  u32 decrypted[4];
  aes256_decrypt (ks, first_block, decrypted, s_td0, s_td1, s_td2, s_td3, s_td4);
    
  const u32 plain0 = decrypted[0] ^ ctx.h[0];
  const u32 masked0 = plain0 & header_mask[0];

  // does this make sense on a GPU?
  if(masked0 != known_header[0]) return;

  const u32 plain1 = decrypted[1] ^ ctx.h[1];
  const u32 plain2 = decrypted[2] ^ ctx.h[2];
  const u32 plain3 = decrypted[3] ^ ctx.h[3];
  const u32 masked1 = plain1 & header_mask[1];
  const u32 masked2 = plain2 & header_mask[2];
  const u32 masked3 = plain3 & header_mask[3];
  
  //printf ("last: %08x-%08x-%08x-%08x\n", plain0, plain1, plain2, plain3);
  //printf ("hmsk: %08x-%08x-%08x-%08x\n", header_mask[0], header_mask[1], header_mask[2], header_mask[3]);
  //printf ("mskd: %08x-%08x-%08x-%08x\n", masked0, masked1, masked2, masked3);

  if ((masked1 == known_header[1])
     && (masked2 == known_header[2])
     && (masked3 == known_header[3]))
    {
      //printf ("found: %08x-%08x-%08x-%08x\n", plain0, plain1, plain2, plain3);
      const u32 final_hash_pos = digests_offset + 0;
      if (atomic_inc (&hashes_shown[final_hash_pos]) == 0)
      {
        mark_hash (plains_buf, d_return_buf, salt_pos, digests_cnt, 0, final_hash_pos, gid, 0, 0, 0);
      }
    }
}
