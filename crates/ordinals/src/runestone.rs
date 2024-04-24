use {super::*, flag::Flag, message::Message, tag::Tag};

mod flag;
mod message;
mod tag;

#[derive(Default, Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct Runestone {
  pub edicts: Vec<Edict>,
  pub etching: Option<Etching>,
  pub mint: Option<RuneId>,
  pub pointer: Option<u32>,
}

#[derive(Debug, PartialEq)]
enum Payload {
  Valid(Vec<u8>),
  Invalid(Flaw),
}

impl Runestone {
  pub const MAGIC_NUMBER: opcodes::All = opcodes::all::OP_PUSHNUM_13;
  pub const COMMIT_CONFIRMATIONS: u16 = 6;

  pub fn decipher(transaction: &Transaction) -> Option<Artifact> {
    let payload = match Runestone::payload(transaction) {
      Some(Payload::Valid(payload)) => payload,
      Some(Payload::Invalid(flaw)) => {
        return Some(Artifact::Cenotaph(Cenotaph {
          flaw: Some(flaw),
          ..default()
        }));
      }
      None => return None,
    };

    let Ok(integers) = Runestone::integers(&payload) else {
      return Some(Artifact::Cenotaph(Cenotaph {
        flaw: Some(Flaw::Varint),
        ..default()
      }));
    };

    let Message {
      mut flaw,
      edicts,
      mut fields,
    } = Message::from_integers(transaction, &integers);

    let mut flags = Tag::Flags
      .take(&mut fields, |[flags]| Some(flags))
      .unwrap_or_default();

    let etching = Flag::Etching.take(&mut flags).then(|| Etching {
      divisibility: Tag::Divisibility.take(&mut fields, |[divisibility]| {
        let divisibility = u8::try_from(divisibility).ok()?;
        (divisibility <= Etching::MAX_DIVISIBILITY).then_some(divisibility)
      }),
      premine: Tag::Premine.take(&mut fields, |[premine]| Some(premine)),
      rune: Tag::Rune.take(&mut fields, |[rune]| Some(Rune(rune))),
      spacers: Tag::Spacers.take(&mut fields, |[spacers]| {
        let spacers = u32::try_from(spacers).ok()?;
        (spacers <= Etching::MAX_SPACERS).then_some(spacers)
      }),
      symbol: Tag::Symbol.take(&mut fields, |[symbol]| {
        char::from_u32(u32::try_from(symbol).ok()?)
      }),
      terms: Flag::Terms.take(&mut flags).then(|| Terms {
        cap: Tag::Cap.take(&mut fields, |[cap]| Some(cap)),
        height: (
          Tag::HeightStart.take(&mut fields, |[start_height]| {
            u64::try_from(start_height).ok()
          }),
          Tag::HeightEnd.take(&mut fields, |[start_height]| {
            u64::try_from(start_height).ok()
          }),
        ),
        amount: Tag::Amount.take(&mut fields, |[amount]| Some(amount)),
        offset: (
          Tag::OffsetStart.take(&mut fields, |[start_offset]| {
            u64::try_from(start_offset).ok()
          }),
          Tag::OffsetEnd.take(&mut fields, |[end_offset]| u64::try_from(end_offset).ok()),
        ),
      }),
      turbo: Flag::Turbo.take(&mut flags),
    });

    let mint = Tag::Mint.take(&mut fields, |[block, tx]| {
      RuneId::new(block.try_into().ok()?, tx.try_into().ok()?)
    });

    let pointer = Tag::Pointer.take(&mut fields, |[pointer]| {
      let pointer = u32::try_from(pointer).ok()?;
      (u64::from(pointer) < u64::try_from(transaction.output.len()).unwrap()).then_some(pointer)
    });

    if etching
      .map(|etching| etching.supply().is_none())
      .unwrap_or_default()
    {
      flaw.get_or_insert(Flaw::SupplyOverflow);
    }

    if flags != 0 {
      flaw.get_or_insert(Flaw::UnrecognizedFlag);
    }

    if fields.keys().any(|tag| tag % 2 == 0) {
      flaw.get_or_insert(Flaw::UnrecognizedEvenTag);
    }

    if let Some(flaw) = flaw {
      return Some(Artifact::Cenotaph(Cenotaph {
        flaw: Some(flaw),
        mint,
        etching: etching.and_then(|etching| etching.rune),
      }));
    }

    Some(Artifact::Runestone(Self {
      edicts,
      etching,
      mint,
      pointer,
    }))
  }

  pub fn encipher(&self) -> ScriptBuf {
    let mut payload = Vec::new();

    if let Some(etching) = self.etching {
      let mut flags = 0;
      Flag::Etching.set(&mut flags);

      if etching.terms.is_some() {
        Flag::Terms.set(&mut flags);
      }

      if etching.turbo {
        Flag::Turbo.set(&mut flags);
      }

      Tag::Flags.encode([flags], &mut payload);

      Tag::Rune.encode_option(etching.rune.map(|rune| rune.0), &mut payload);
      Tag::Divisibility.encode_option(etching.divisibility, &mut payload);
      Tag::Spacers.encode_option(etching.spacers, &mut payload);
      Tag::Symbol.encode_option(etching.symbol, &mut payload);
      Tag::Premine.encode_option(etching.premine, &mut payload);

      if let Some(terms) = etching.terms {
        Tag::Amount.encode_option(terms.amount, &mut payload);
        Tag::Cap.encode_option(terms.cap, &mut payload);
        Tag::HeightStart.encode_option(terms.height.0, &mut payload);
        Tag::HeightEnd.encode_option(terms.height.1, &mut payload);
        Tag::OffsetStart.encode_option(terms.offset.0, &mut payload);
        Tag::OffsetEnd.encode_option(terms.offset.1, &mut payload);
      }
    }

    if let Some(RuneId { block, tx }) = self.mint {
      Tag::Mint.encode([block.into(), tx.into()], &mut payload);
    }

    Tag::Pointer.encode_option(self.pointer, &mut payload);

    if !self.edicts.is_empty() {
      varint::encode_to_vec(Tag::Body.into(), &mut payload);

      let mut edicts = self.edicts.clone();
      edicts.sort_by_key(|edict| edict.id);

      let mut previous = RuneId::default();
      for edict in edicts {
        let (block, tx) = previous.delta(edict.id).unwrap();
        varint::encode_to_vec(block, &mut payload);
        varint::encode_to_vec(tx, &mut payload);
        varint::encode_to_vec(edict.amount, &mut payload);
        varint::encode_to_vec(edict.output.into(), &mut payload);
        previous = edict.id;
      }
    }

    let mut builder = script::Builder::new()
      .push_opcode(opcodes::all::OP_RETURN)
      .push_opcode(Runestone::MAGIC_NUMBER);

    for chunk in payload.chunks(MAX_SCRIPT_ELEMENT_SIZE) {
      let push: &script::PushBytes = chunk.try_into().unwrap();
      builder = builder.push_slice(push);
    }

    builder.into_script()
  }

  fn payload(transaction: &Transaction) -> Option<Payload> {
    // search transaction outputs for payload
    for output in &transaction.output {
      let mut instructions = output.script_pubkey.instructions();

      // payload starts with OP_RETURN
      if instructions.next() != Some(Ok(Instruction::Op(opcodes::all::OP_RETURN))) {
        continue;
      }

      // followed by the protocol identifier, ignoring errors, since OP_RETURN
      // scripts may be invalid
      if instructions.next() != Some(Ok(Instruction::Op(Runestone::MAGIC_NUMBER))) {
        continue;
      }

      // construct the payload by concatenating remaining data pushes
      let mut payload = Vec::new();

      for result in instructions {
        match result {
          Ok(Instruction::PushBytes(push)) => {
            payload.extend_from_slice(push.as_bytes());
          }
          Ok(Instruction::Op(_)) => {
            return Some(Payload::Invalid(Flaw::Opcode));
          }
          Err(_) => {
            return Some(Payload::Invalid(Flaw::InvalidScript));
          }
        }
      }

      return Some(Payload::Valid(payload));
    }

    None
  }

  fn integers(payload: &[u8]) -> Result<Vec<u128>, varint::Error> {
    let mut integers = Vec::new();
    let mut i = 0;

    while i < payload.len() {
      let (integer, length) = varint::decode(&payload[i..])?;
      integers.push(integer);
      i += length;
    }

    Ok(integers)
  }
}

#[cfg(test)]
mod tests {
  use {
    super::*,
    bitcoin::{
      blockdata::locktime::absolute::LockTime, script::PushBytes, Sequence, TxIn, TxOut, Witness,
    },
    hex::FromHex,
    pretty_assertions::assert_eq,
  };

  pub(crate) fn rune_id(tx: u32) -> RuneId {
    RuneId { block: 1, tx }
  }

  fn decipher(integers: &[u128]) -> Artifact {
    let payload = payload(integers);

    let payload: &PushBytes = payload.as_slice().try_into().unwrap();

    Runestone::decipher(&Transaction {
      input: Vec::new(),
      output: vec![TxOut {
        script_pubkey: script::Builder::new()
          .push_opcode(opcodes::all::OP_RETURN)
          .push_opcode(Runestone::MAGIC_NUMBER)
          .push_slice(payload)
          .into_script(),
        value: 0,
      }],
      lock_time: LockTime::ZERO,
      version: 2,
    })
    .unwrap()
  }

  fn payload(integers: &[u128]) -> Vec<u8> {
    let mut payload = Vec::new();

    for integer in integers {
      payload.extend(varint::encode(*integer));
    }

    payload
  }

  #[test]
  fn test_decipher_transaction() {
    //let tx_raw = "020000000001017fb9cc941aa0ca3aaf339783564d2d29ec3254a9128f5d49ad3eeb002aeb40ec0000000000000000000242342a6b000000002251203b8b3ab1453eb47e2d4903b963776680e30863df3625d3e74292338ae7928da10000000000000000246a5d21020704b5e1d8e1c8eeb788a30705a02d039f3e01020680dc9afd2808c7e8430a640340924b2624416402a52ed7cf4eba6b2c535d2def8e649a74ed97aaca5ec54881ef3b34da68bb13d76d6b420e60297a9247cb081d1e59cb2c260b1509cff25d4b3158204c04e894d5357840e324b24c959ca6a5082035f6ffae12f331202bc84bf4612eac0063036f7264010b2047f22ed15d3082f5e9a005864528e4f991ade841a9c5846e2c118425878b6be1010d09b530368c74df10a3036821c04c04e894d5357840e324b24c959ca6a5082035f6ffae12f331202bc84bf4612e00000000";
    let tx_raw = "020000000001010524ce296bb611f135812f67edc6660db0849e9506f62d07fa980d22deef40980000000000f5ffffff03102700000000000022512003fe4156899a8f727e5272155523c3befaf1122ee8d6237bdf9fdde740035f25e80300000000000022512003fe4156899a8f727e5272155523c3befaf1122ee8d6237bdf9fdde740035f250000000000000000306a5d2d020704aee8bebeb8aed3aff0ee1301020344054d06a08d060a904e085a0ce0fa9d010ec8829e01100a125a16010340b5a1a4e8b1691eddf44f5c8b0d0acb708f6df3daa5a020b92859947170ca771320e2bc15be1d85407d072462f9dd8019b581b3a56fbfba23679ce5695a3d71773720f23755fcb6b5b789c67ea897248a1b5c5f9d91867556c9d7c56d574dac8e4c96ac0063036f726401010a696d6167652f77656270006821c0f23755fcb6b5b789c67ea897248a1b5c5f9d91867556c9d7c56d574dac8e4c9600000000"; //failed
    let raw_tx = hex::decode(tx_raw).unwrap();
    let tx: Transaction =
      Decodable::consensus_decode(&mut raw_tx.as_slice()).expect("failed to decode transaction");

    let Some(artifact) = Runestone::decipher(&tx) else {
      println!("failed to decipher transaction ");
      return;
    };
    println!("artifact: {:?}", artifact);
  }

  #[test]
  fn test_payload() {
    let tx_raw = "020000000001017fb9cc941aa0ca3aaf339783564d2d29ec3254a9128f5d49ad3eeb002aeb40ec0000000000000000000242342a6b000000002251203b8b3ab1453eb47e2d4903b963776680e30863df3625d3e74292338ae7928da10000000000000000246a5d21020704b5e1d8e1c8eeb788a30705a02d039f3e01020680dc9afd2808c7e8430a640340924b2624416402a52ed7cf4eba6b2c535d2def8e649a74ed97aaca5ec54881ef3b34da68bb13d76d6b420e60297a9247cb081d1e59cb2c260b1509cff25d4b3158204c04e894d5357840e324b24c959ca6a5082035f6ffae12f331202bc84bf4612eac0063036f7264010b2047f22ed15d3082f5e9a005864528e4f991ade841a9c5846e2c118425878b6be1010d09b530368c74df10a3036821c04c04e894d5357840e324b24c959ca6a5082035f6ffae12f331202bc84bf4612e00000000";
    //let tx_raw = "020000000001017fb9cc941aa0ca3aaf339783564d2d29ec3254a9128f5d49ad3eeb002aeb40ec0000000000000000000242342a6b000000002251203b8b3ab1453eb47e2d4903b963776680e30863df3625d3e74292338ae7928da10000000000000000246a5d21020704b5e1d8e1c8eeb788a30705a02d039f3e01020680dc9afd2808c7e8430a640340924b2624416402a52ed7cf4eba6b2c535d2def8e649a74ed97aaca5ec54881ef3b34da68bb13d76d6b420e60297a9247cb081d1e59cb2c260b1509cff25d4b3158204c04e894d5357840e324b24c959ca6a5082035f6ffae12f331202bc84bf4612eac0063036f7264010b2047f22ed15d3082f5e9a005864528e4f991ade841a9c5846e2c118425878b6be1010d09b530368c74df10a3036821c04c04e894d5357840e324b24c959ca6a5082035f6ffae12f331202bc84bf4612e00000000";
    let raw_tx = hex::decode(tx_raw).unwrap();
    let tx: Transaction =
      Decodable::consensus_decode(&mut raw_tx.as_slice()).expect("failed to decode transaction");
    let payload = match Runestone::payload(&tx) {
      Some(Payload::Valid(payload)) => payload,
      Some(Payload::Invalid(flaw)) => {
        println!("flaw : {:?}", flaw);
        return;
      }
      None => return,
    };
    println!("payload : {:?}", payload);
    let Ok(integers) = Runestone::integers(&payload) else {
      println!("failed to parse payload");
      return;
    };
    println!("integers : {:?}", integers);
  }

  #[test]
  fn test_decipher_payload() {
    let script_pubkey =
      "2c020704c2bbf89fbdd5a5e4e66101020344054d06a08d060a904e085a0ce0fa9d010ec8829e01100a125a1601";
    let tx = Transaction {
      input: Vec::new(),
      output: vec![TxOut {
        script_pubkey: ScriptBuf::from_bytes(hex::decode(script_pubkey).unwrap()),
        value: 0,
      }],
      lock_time: LockTime::ZERO,
      version: 2,
    };
    println!("tx: {:?}", tx);
    let res = Runestone::decipher(&tx);
    println!("res: {:?}", res);
  }
  #[test]
  fn decipher_returns_none_if_first_opcode_is_malformed() {
    assert_eq!(
      Runestone::decipher(&Transaction {
        input: Vec::new(),
        output: vec![TxOut {
          script_pubkey: ScriptBuf::from_bytes(vec![opcodes::all::OP_PUSHBYTES_4.to_u8()]),
          value: 0,
        }],
        lock_time: LockTime::ZERO,
        version: 2,
      }),
      None,
    );
  }

  #[test]
  fn deciphering_transaction_with_no_outputs_returns_none() {
    assert_eq!(
      Runestone::decipher(&Transaction {
        input: Vec::new(),
        output: Vec::new(),
        lock_time: LockTime::ZERO,
        version: 2,
      }),
      None,
    );
  }

  #[test]
  fn deciphering_transaction_with_non_op_return_output_returns_none() {
    assert_eq!(
      Runestone::decipher(&Transaction {
        input: Vec::new(),
        output: vec![TxOut {
          script_pubkey: script::Builder::new().push_slice([]).into_script(),
          value: 0
        }],
        lock_time: LockTime::ZERO,
        version: 2,
      }),
      None,
    );
  }

  #[test]
  fn deciphering_transaction_with_bare_op_return_returns_none() {
    assert_eq!(
      Runestone::decipher(&Transaction {
        input: Vec::new(),
        output: vec![TxOut {
          script_pubkey: script::Builder::new()
            .push_opcode(opcodes::all::OP_RETURN)
            .into_script(),
          value: 0
        }],
        lock_time: LockTime::ZERO,
        version: 2,
      }),
      None,
    );
  }

  #[test]
  fn deciphering_transaction_with_non_matching_op_return_returns_none() {
    assert_eq!(
      Runestone::decipher(&Transaction {
        input: Vec::new(),
        output: vec![TxOut {
          script_pubkey: script::Builder::new()
            .push_opcode(opcodes::all::OP_RETURN)
            .push_slice(b"FOOO")
            .into_script(),
          value: 0
        }],
        lock_time: LockTime::ZERO,
        version: 2,
      }),
      None,
    );
  }

  #[test]
  fn deciphering_valid_runestone_with_invalid_script_postfix_returns_invalid_payload() {
    let mut script_pubkey = script::Builder::new()
      .push_opcode(opcodes::all::OP_RETURN)
      .push_opcode(Runestone::MAGIC_NUMBER)
      .into_script()
      .into_bytes();

    script_pubkey.push(opcodes::all::OP_PUSHBYTES_4.to_u8());

    assert_eq!(
      Runestone::payload(&Transaction {
        input: Vec::new(),
        output: vec![TxOut {
          script_pubkey: ScriptBuf::from_bytes(script_pubkey),
          value: 0,
        }],
        lock_time: LockTime::ZERO,
        version: 2,
      }),
      Some(Payload::Invalid(Flaw::InvalidScript))
    );
  }

  #[test]
  fn deciphering_runestone_with_truncated_varint_succeeds() {
    Runestone::decipher(&Transaction {
      input: Vec::new(),
      output: vec![TxOut {
        script_pubkey: script::Builder::new()
          .push_opcode(opcodes::all::OP_RETURN)
          .push_opcode(Runestone::MAGIC_NUMBER)
          .push_slice([128])
          .into_script(),
        value: 0,
      }],
      lock_time: LockTime::ZERO,
      version: 2,
    })
    .unwrap();
  }

  #[test]
  fn outputs_with_non_pushdata_opcodes_are_cenotaph() {
    assert_eq!(
      Runestone::decipher(&Transaction {
        input: Vec::new(),
        output: vec![
          TxOut {
            script_pubkey: script::Builder::new()
              .push_opcode(opcodes::all::OP_RETURN)
              .push_opcode(Runestone::MAGIC_NUMBER)
              .push_opcode(opcodes::all::OP_VERIFY)
              .push_slice([0])
              .push_slice::<&PushBytes>(varint::encode(1).as_slice().try_into().unwrap())
              .push_slice::<&PushBytes>(varint::encode(1).as_slice().try_into().unwrap())
              .push_slice([2, 0])
              .into_script(),
            value: 0,
          },
          TxOut {
            script_pubkey: script::Builder::new()
              .push_opcode(opcodes::all::OP_RETURN)
              .push_opcode(Runestone::MAGIC_NUMBER)
              .push_slice([0])
              .push_slice::<&PushBytes>(varint::encode(1).as_slice().try_into().unwrap())
              .push_slice::<&PushBytes>(varint::encode(2).as_slice().try_into().unwrap())
              .push_slice([3, 0])
              .into_script(),
            value: 0,
          },
        ],
        lock_time: LockTime::ZERO,
        version: 2,
      })
      .unwrap(),
      Artifact::Cenotaph(Cenotaph {
        flaw: Some(Flaw::Opcode),
        ..default()
      }),
    );
  }

  #[test]
  fn pushnum_opcodes_in_runestone_produce_cenotaph() {
    assert_eq!(
      Runestone::decipher(&Transaction {
        input: Vec::new(),
        output: vec![TxOut {
          script_pubkey: script::Builder::new()
            .push_opcode(opcodes::all::OP_RETURN)
            .push_opcode(Runestone::MAGIC_NUMBER)
            .push_opcode(opcodes::all::OP_PUSHNUM_1)
            .into_script(),
          value: 0,
        },],
        lock_time: LockTime::ZERO,
        version: 2,
      })
      .unwrap(),
      Artifact::Cenotaph(Cenotaph {
        flaw: Some(Flaw::Opcode),
        ..default()
      }),
    );
  }

  #[test]
  fn deciphering_empty_runestone_is_successful() {
    assert_eq!(
      Runestone::decipher(&Transaction {
        input: Vec::new(),
        output: vec![TxOut {
          script_pubkey: script::Builder::new()
            .push_opcode(opcodes::all::OP_RETURN)
            .push_opcode(Runestone::MAGIC_NUMBER)
            .into_script(),
          value: 0
        }],
        lock_time: LockTime::ZERO,
        version: 2,
      })
      .unwrap(),
      Artifact::Runestone(Runestone::default()),
    );
  }

  #[test]
  fn invalid_input_scripts_are_skipped_when_searching_for_runestone() {
    let payload = payload(&[Tag::Mint.into(), 1, Tag::Mint.into(), 1]);

    let payload: &PushBytes = payload.as_slice().try_into().unwrap();

    let script_pubkey = vec![
      opcodes::all::OP_RETURN.to_u8(),
      opcodes::all::OP_PUSHBYTES_9.to_u8(),
      Runestone::MAGIC_NUMBER.to_u8(),
      opcodes::all::OP_PUSHBYTES_4.to_u8(),
    ];

    assert_eq!(
      Runestone::decipher(&Transaction {
        input: Vec::new(),
        output: vec![
          TxOut {
            script_pubkey: ScriptBuf::from_bytes(script_pubkey),
            value: 0,
          },
          TxOut {
            script_pubkey: script::Builder::new()
              .push_opcode(opcodes::all::OP_RETURN)
              .push_opcode(Runestone::MAGIC_NUMBER)
              .push_slice(payload)
              .into_script(),
            value: 0,
          },
        ],
        lock_time: LockTime::ZERO,
        version: 2,
      })
      .unwrap(),
      Artifact::Runestone(Runestone {
        mint: Some(RuneId::new(1, 1).unwrap()),
        ..default()
      }),
    );
  }

  #[test]
  fn deciphering_non_empty_runestone_is_successful() {
    assert_eq!(
      decipher(&[Tag::Body.into(), 1, 1, 2, 0]),
      Artifact::Runestone(Runestone {
        edicts: vec![Edict {
          id: rune_id(1),
          amount: 2,
          output: 0,
        }],
        ..default()
      }),
    );
  }

  #[test]
  fn decipher_etching() {
    assert_eq!(
      decipher(&[
        Tag::Flags.into(),
        Flag::Etching.mask(),
        Tag::Body.into(),
        1,
        1,
        2,
        0
      ]),
      Artifact::Runestone(Runestone {
        edicts: vec![Edict {
          id: rune_id(1),
          amount: 2,
          output: 0,
        }],
        etching: Some(Etching::default()),
        ..default()
      }),
    );
  }

  #[test]
  fn decipher_etching_with_rune() {
    assert_eq!(
      decipher(&[
        Tag::Flags.into(),
        Flag::Etching.mask(),
        Tag::Rune.into(),
        4,
        Tag::Body.into(),
        1,
        1,
        2,
        0
      ]),
      Artifact::Runestone(Runestone {
        edicts: vec![Edict {
          id: rune_id(1),
          amount: 2,
          output: 0,
        }],
        etching: Some(Etching {
          rune: Some(Rune(4)),
          ..default()
        }),
        ..default()
      }),
    );
  }

  #[test]
  fn terms_flag_without_etching_flag_produces_cenotaph() {
    assert_eq!(
      decipher(&[
        Tag::Flags.into(),
        Flag::Terms.mask(),
        Tag::Body.into(),
        0,
        0,
        0,
        0
      ]),
      Artifact::Cenotaph(Cenotaph {
        flaw: Some(Flaw::UnrecognizedFlag),
        ..default()
      }),
    );
  }

  #[test]
  fn recognized_fields_without_flag_produces_cenotaph() {
    #[track_caller]
    fn case(integers: &[u128]) {
      assert_eq!(
        decipher(integers),
        Artifact::Cenotaph(Cenotaph {
          flaw: Some(Flaw::UnrecognizedEvenTag),
          ..default()
        }),
      );
    }

    case(&[Tag::Premine.into(), 0]);
    case(&[Tag::Rune.into(), 0]);
    case(&[Tag::Cap.into(), 0]);
    case(&[Tag::Amount.into(), 0]);
    case(&[Tag::OffsetStart.into(), 0]);
    case(&[Tag::OffsetEnd.into(), 0]);
    case(&[Tag::HeightStart.into(), 0]);
    case(&[Tag::HeightEnd.into(), 0]);

    case(&[Tag::Flags.into(), Flag::Etching.into(), Tag::Cap.into(), 0]);
    case(&[
      Tag::Flags.into(),
      Flag::Etching.into(),
      Tag::Amount.into(),
      0,
    ]);
    case(&[
      Tag::Flags.into(),
      Flag::Etching.into(),
      Tag::OffsetStart.into(),
      0,
    ]);
    case(&[
      Tag::Flags.into(),
      Flag::Etching.into(),
      Tag::OffsetEnd.into(),
      0,
    ]);
    case(&[
      Tag::Flags.into(),
      Flag::Etching.into(),
      Tag::HeightStart.into(),
      0,
    ]);
    case(&[
      Tag::Flags.into(),
      Flag::Etching.into(),
      Tag::HeightEnd.into(),
      0,
    ]);
  }

  #[test]
  fn decipher_etching_with_term() {
    assert_eq!(
      decipher(&[
        Tag::Flags.into(),
        Flag::Etching.mask() | Flag::Terms.mask(),
        Tag::OffsetEnd.into(),
        4,
        Tag::Body.into(),
        1,
        1,
        2,
        0
      ]),
      Artifact::Runestone(Runestone {
        edicts: vec![Edict {
          id: rune_id(1),
          amount: 2,
          output: 0,
        }],
        etching: Some(Etching {
          terms: Some(Terms {
            offset: (None, Some(4)),
            ..default()
          }),
          ..default()
        }),
        ..default()
      }),
    );
  }

  #[test]
  fn decipher_etching_with_amount() {
    assert_eq!(
      decipher(&[
        Tag::Flags.into(),
        Flag::Etching.mask() | Flag::Terms.mask(),
        Tag::Amount.into(),
        4,
        Tag::Body.into(),
        1,
        1,
        2,
        0
      ]),
      Artifact::Runestone(Runestone {
        edicts: vec![Edict {
          id: rune_id(1),
          amount: 2,
          output: 0,
        }],
        etching: Some(Etching {
          terms: Some(Terms {
            amount: Some(4),
            ..default()
          }),
          ..default()
        }),
        ..default()
      }),
    );
  }

  #[test]
  fn invalid_varint_produces_cenotaph() {
    assert_eq!(
      Runestone::decipher(&Transaction {
        input: Vec::new(),
        output: vec![TxOut {
          script_pubkey: script::Builder::new()
            .push_opcode(opcodes::all::OP_RETURN)
            .push_opcode(Runestone::MAGIC_NUMBER)
            .push_slice([128])
            .into_script(),
          value: 0,
        }],
        lock_time: LockTime::ZERO,
        version: 2,
      })
      .unwrap(),
      Artifact::Cenotaph(Cenotaph {
        flaw: Some(Flaw::Varint),
        ..default()
      }),
    );
  }

  #[test]
  fn duplicate_even_tags_produce_cenotaph() {
    assert_eq!(
      decipher(&[
        Tag::Flags.into(),
        Flag::Etching.mask(),
        Tag::Rune.into(),
        4,
        Tag::Rune.into(),
        5,
        Tag::Body.into(),
        1,
        1,
        2,
        0,
      ]),
      Artifact::Cenotaph(Cenotaph {
        flaw: Some(Flaw::UnrecognizedEvenTag),
        etching: Some(Rune(4)),
        ..default()
      }),
    );
  }

  #[test]
  fn duplicate_odd_tags_are_ignored() {
    assert_eq!(
      decipher(&[
        Tag::Flags.into(),
        Flag::Etching.mask(),
        Tag::Divisibility.into(),
        4,
        Tag::Divisibility.into(),
        5,
        Tag::Body.into(),
        1,
        1,
        2,
        0,
      ]),
      Artifact::Runestone(Runestone {
        edicts: vec![Edict {
          id: rune_id(1),
          amount: 2,
          output: 0,
        }],
        etching: Some(Etching {
          rune: None,
          divisibility: Some(4),
          ..default()
        }),
        ..default()
      })
    );
  }

  #[test]
  fn unrecognized_odd_tag_is_ignored() {
    assert_eq!(
      decipher(&[Tag::Nop.into(), 100, Tag::Body.into(), 1, 1, 2, 0]),
      Artifact::Runestone(Runestone {
        edicts: vec![Edict {
          id: rune_id(1),
          amount: 2,
          output: 0,
        }],
        ..default()
      }),
    );
  }

  #[test]
  fn runestone_with_unrecognized_even_tag_is_cenotaph() {
    assert_eq!(
      decipher(&[Tag::Cenotaph.into(), 0, Tag::Body.into(), 1, 1, 2, 0]),
      Artifact::Cenotaph(Cenotaph {
        flaw: Some(Flaw::UnrecognizedEvenTag),
        ..default()
      }),
    );
  }

  #[test]
  fn runestone_with_unrecognized_flag_is_cenotaph() {
    assert_eq!(
      decipher(&[
        Tag::Flags.into(),
        Flag::Cenotaph.mask(),
        Tag::Body.into(),
        1,
        1,
        2,
        0
      ]),
      Artifact::Cenotaph(Cenotaph {
        flaw: Some(Flaw::UnrecognizedFlag),
        ..default()
      }),
    );
  }

  #[test]
  fn runestone_with_edict_id_with_zero_block_and_nonzero_tx_is_cenotaph() {
    assert_eq!(
      decipher(&[Tag::Body.into(), 0, 1, 2, 0]),
      Artifact::Cenotaph(Cenotaph {
        flaw: Some(Flaw::EdictRuneId),
        ..default()
      }),
    );
  }

  #[test]
  fn runestone_with_overflowing_edict_id_delta_is_cenotaph() {
    assert_eq!(
      decipher(&[Tag::Body.into(), 1, 0, 0, 0, u64::MAX.into(), 0, 0, 0]),
      Artifact::Cenotaph(Cenotaph {
        flaw: Some(Flaw::EdictRuneId),
        ..default()
      }),
    );

    assert_eq!(
      decipher(&[Tag::Body.into(), 1, 1, 0, 0, 0, u64::MAX.into(), 0, 0]),
      Artifact::Cenotaph(Cenotaph {
        flaw: Some(Flaw::EdictRuneId),
        ..default()
      }),
    );
  }

  #[test]
  fn runestone_with_output_over_max_is_cenotaph() {
    assert_eq!(
      decipher(&[Tag::Body.into(), 1, 1, 2, 2]),
      Artifact::Cenotaph(Cenotaph {
        flaw: Some(Flaw::EdictOutput),
        ..default()
      }),
    );
  }

  #[test]
  fn tag_with_no_value_is_cenotaph() {
    assert_eq!(
      decipher(&[Tag::Flags.into(), 1, Tag::Flags.into()]),
      Artifact::Cenotaph(Cenotaph {
        flaw: Some(Flaw::TruncatedField),
        ..default()
      }),
    );
  }

  #[test]
  fn trailing_integers_in_body_is_cenotaph() {
    let mut integers = vec![Tag::Body.into(), 1, 1, 2, 0];

    for i in 0..4 {
      assert_eq!(
        decipher(&integers),
        if i == 0 {
          Artifact::Runestone(Runestone {
            edicts: vec![Edict {
              id: rune_id(1),
              amount: 2,
              output: 0,
            }],
            ..default()
          })
        } else {
          Artifact::Cenotaph(Cenotaph {
            flaw: Some(Flaw::TrailingIntegers),
            ..default()
          })
        }
      );

      integers.push(0);
    }
  }

  #[test]
  fn decipher_etching_with_divisibility() {
    assert_eq!(
      decipher(&[
        Tag::Flags.into(),
        Flag::Etching.mask(),
        Tag::Rune.into(),
        4,
        Tag::Divisibility.into(),
        5,
        Tag::Body.into(),
        1,
        1,
        2,
        0,
      ]),
      Artifact::Runestone(Runestone {
        edicts: vec![Edict {
          id: rune_id(1),
          amount: 2,
          output: 0,
        }],
        etching: Some(Etching {
          rune: Some(Rune(4)),
          divisibility: Some(5),
          ..default()
        }),
        ..default()
      }),
    );
  }

  #[test]
  fn divisibility_above_max_is_ignored() {
    assert_eq!(
      decipher(&[
        Tag::Flags.into(),
        Flag::Etching.mask(),
        Tag::Rune.into(),
        4,
        Tag::Divisibility.into(),
        (Etching::MAX_DIVISIBILITY + 1).into(),
        Tag::Body.into(),
        1,
        1,
        2,
        0,
      ]),
      Artifact::Runestone(Runestone {
        edicts: vec![Edict {
          id: rune_id(1),
          amount: 2,
          output: 0,
        }],
        etching: Some(Etching {
          rune: Some(Rune(4)),
          ..default()
        }),
        ..default()
      }),
    );
  }

  #[test]
  fn symbol_above_max_is_ignored() {
    assert_eq!(
      decipher(&[
        Tag::Flags.into(),
        Flag::Etching.mask(),
        Tag::Symbol.into(),
        u128::from(u32::from(char::MAX) + 1),
        Tag::Body.into(),
        1,
        1,
        2,
        0,
      ]),
      Artifact::Runestone(Runestone {
        edicts: vec![Edict {
          id: rune_id(1),
          amount: 2,
          output: 0,
        }],
        etching: Some(Etching::default()),
        ..default()
      }),
    );
  }

  #[test]
  fn decipher_etching_with_symbol() {
    assert_eq!(
      decipher(&[
        Tag::Flags.into(),
        Flag::Etching.mask(),
        Tag::Rune.into(),
        4,
        Tag::Symbol.into(),
        'a'.into(),
        Tag::Body.into(),
        1,
        1,
        2,
        0,
      ]),
      Artifact::Runestone(Runestone {
        edicts: vec![Edict {
          id: rune_id(1),
          amount: 2,
          output: 0,
        }],
        etching: Some(Etching {
          rune: Some(Rune(4)),
          symbol: Some('a'),
          ..default()
        }),
        ..default()
      }),
    );
  }

  #[test]
  fn decipher_etching_with_all_etching_tags() {
    assert_eq!(
      decipher(&[
        Tag::Flags.into(),
        Flag::Etching.mask() | Flag::Terms.mask() | Flag::Turbo.mask(),
        Tag::Rune.into(),
        4,
        Tag::Divisibility.into(),
        1,
        Tag::Spacers.into(),
        5,
        Tag::Symbol.into(),
        'a'.into(),
        Tag::OffsetEnd.into(),
        2,
        Tag::Amount.into(),
        3,
        Tag::Premine.into(),
        8,
        Tag::Cap.into(),
        9,
        Tag::Pointer.into(),
        0,
        Tag::Mint.into(),
        1,
        Tag::Mint.into(),
        1,
        Tag::Body.into(),
        1,
        1,
        2,
        0,
      ]),
      Artifact::Runestone(Runestone {
        edicts: vec![Edict {
          id: rune_id(1),
          amount: 2,
          output: 0,
        }],
        etching: Some(Etching {
          divisibility: Some(1),
          premine: Some(8),
          rune: Some(Rune(4)),
          spacers: Some(5),
          symbol: Some('a'),
          terms: Some(Terms {
            cap: Some(9),
            offset: (None, Some(2)),
            amount: Some(3),
            height: (None, None),
          }),
          turbo: true,
        }),
        pointer: Some(0),
        mint: Some(RuneId::new(1, 1).unwrap()),
      }),
    );
  }

  #[test]
  fn recognized_even_etching_fields_produce_cenotaph_if_etching_flag_is_not_set() {
    assert_eq!(
      decipher(&[Tag::Rune.into(), 4]),
      Artifact::Cenotaph(Cenotaph {
        flaw: Some(Flaw::UnrecognizedEvenTag),
        ..default()
      }),
    );
  }

  #[test]
  fn decipher_etching_with_divisibility_and_symbol() {
    assert_eq!(
      decipher(&[
        Tag::Flags.into(),
        Flag::Etching.mask(),
        Tag::Rune.into(),
        4,
        Tag::Divisibility.into(),
        1,
        Tag::Symbol.into(),
        'a'.into(),
        Tag::Body.into(),
        1,
        1,
        2,
        0,
      ]),
      Artifact::Runestone(Runestone {
        edicts: vec![Edict {
          id: rune_id(1),
          amount: 2,
          output: 0,
        }],
        etching: Some(Etching {
          rune: Some(Rune(4)),
          divisibility: Some(1),
          symbol: Some('a'),
          ..default()
        }),
        ..default()
      }),
    );
  }

  #[test]
  fn tag_values_are_not_parsed_as_tags() {
    assert_eq!(
      decipher(&[
        Tag::Flags.into(),
        Flag::Etching.mask(),
        Tag::Divisibility.into(),
        Tag::Body.into(),
        Tag::Body.into(),
        1,
        1,
        2,
        0,
      ]),
      Artifact::Runestone(Runestone {
        edicts: vec![Edict {
          id: rune_id(1),
          amount: 2,
          output: 0,
        }],
        etching: Some(Etching {
          divisibility: Some(0),
          ..default()
        }),
        ..default()
      }),
    );
  }

  #[test]
  fn runestone_may_contain_multiple_edicts() {
    assert_eq!(
      decipher(&[Tag::Body.into(), 1, 1, 2, 0, 0, 3, 5, 0]),
      Artifact::Runestone(Runestone {
        edicts: vec![
          Edict {
            id: rune_id(1),
            amount: 2,
            output: 0,
          },
          Edict {
            id: rune_id(4),
            amount: 5,
            output: 0,
          },
        ],
        ..default()
      }),
    );
  }

  #[test]
  fn runestones_with_invalid_rune_id_blocks_are_cenotaph() {
    assert_eq!(
      decipher(&[Tag::Body.into(), 1, 1, 2, 0, u128::MAX, 1, 0, 0,]),
      Artifact::Cenotaph(Cenotaph {
        flaw: Some(Flaw::EdictRuneId),
        ..default()
      }),
    );
  }

  #[test]
  fn runestones_with_invalid_rune_id_txs_are_cenotaph() {
    assert_eq!(
      decipher(&[Tag::Body.into(), 1, 1, 2, 0, 1, u128::MAX, 0, 0,]),
      Artifact::Cenotaph(Cenotaph {
        flaw: Some(Flaw::EdictRuneId),
        ..default()
      }),
    );
  }

  #[test]
  fn payload_pushes_are_concatenated() {
    assert_eq!(
      Runestone::decipher(&Transaction {
        input: Vec::new(),
        output: vec![TxOut {
          script_pubkey: script::Builder::new()
            .push_opcode(opcodes::all::OP_RETURN)
            .push_opcode(Runestone::MAGIC_NUMBER)
            .push_slice::<&PushBytes>(
              varint::encode(Tag::Flags.into())
                .as_slice()
                .try_into()
                .unwrap()
            )
            .push_slice::<&PushBytes>(
              varint::encode(Flag::Etching.mask())
                .as_slice()
                .try_into()
                .unwrap()
            )
            .push_slice::<&PushBytes>(
              varint::encode(Tag::Divisibility.into())
                .as_slice()
                .try_into()
                .unwrap()
            )
            .push_slice::<&PushBytes>(varint::encode(5).as_slice().try_into().unwrap())
            .push_slice::<&PushBytes>(
              varint::encode(Tag::Body.into())
                .as_slice()
                .try_into()
                .unwrap()
            )
            .push_slice::<&PushBytes>(varint::encode(1).as_slice().try_into().unwrap())
            .push_slice::<&PushBytes>(varint::encode(1).as_slice().try_into().unwrap())
            .push_slice::<&PushBytes>(varint::encode(2).as_slice().try_into().unwrap())
            .push_slice::<&PushBytes>(varint::encode(0).as_slice().try_into().unwrap())
            .into_script(),
          value: 0
        }],
        lock_time: LockTime::ZERO,
        version: 2,
      })
      .unwrap(),
      Artifact::Runestone(Runestone {
        edicts: vec![Edict {
          id: rune_id(1),
          amount: 2,
          output: 0,
        }],
        etching: Some(Etching {
          divisibility: Some(5),
          ..default()
        }),
        ..default()
      }),
    );
  }

  #[test]
  fn runestone_may_be_in_second_output() {
    let payload = payload(&[0, 1, 1, 2, 0]);

    let payload: &PushBytes = payload.as_slice().try_into().unwrap();

    assert_eq!(
      Runestone::decipher(&Transaction {
        input: Vec::new(),
        output: vec![
          TxOut {
            script_pubkey: ScriptBuf::new(),
            value: 0,
          },
          TxOut {
            script_pubkey: script::Builder::new()
              .push_opcode(opcodes::all::OP_RETURN)
              .push_opcode(Runestone::MAGIC_NUMBER)
              .push_slice(payload)
              .into_script(),
            value: 0
          }
        ],
        lock_time: LockTime::ZERO,
        version: 2,
      })
      .unwrap(),
      Artifact::Runestone(Runestone {
        edicts: vec![Edict {
          id: rune_id(1),
          amount: 2,
          output: 0,
        }],
        ..default()
      }),
    );
  }

  #[test]
  fn runestone_may_be_after_non_matching_op_return() {
    let payload = payload(&[0, 1, 1, 2, 0]);

    let payload: &PushBytes = payload.as_slice().try_into().unwrap();

    assert_eq!(
      Runestone::decipher(&Transaction {
        input: Vec::new(),
        output: vec![
          TxOut {
            script_pubkey: script::Builder::new()
              .push_opcode(opcodes::all::OP_RETURN)
              .push_slice(b"FOO")
              .into_script(),
            value: 0,
          },
          TxOut {
            script_pubkey: script::Builder::new()
              .push_opcode(opcodes::all::OP_RETURN)
              .push_opcode(Runestone::MAGIC_NUMBER)
              .push_slice(payload)
              .into_script(),
            value: 0
          }
        ],
        lock_time: LockTime::ZERO,
        version: 2,
      })
      .unwrap(),
      Artifact::Runestone(Runestone {
        edicts: vec![Edict {
          id: rune_id(1),
          amount: 2,
          output: 0,
        }],
        ..default()
      })
    );
  }

  #[test]
  fn runestone_size() {
    #[track_caller]
    fn case(edicts: Vec<Edict>, etching: Option<Etching>, size: usize) {
      assert_eq!(
        Runestone {
          edicts,
          etching,
          ..default()
        }
        .encipher()
        .len(),
        size
      );
    }

    case(Vec::new(), None, 2);

    case(
      Vec::new(),
      Some(Etching {
        rune: Some(Rune(0)),
        ..default()
      }),
      7,
    );

    case(
      Vec::new(),
      Some(Etching {
        divisibility: Some(Etching::MAX_DIVISIBILITY),
        rune: Some(Rune(0)),
        ..default()
      }),
      9,
    );

    case(
      Vec::new(),
      Some(Etching {
        divisibility: Some(Etching::MAX_DIVISIBILITY),
        terms: Some(Terms {
          cap: Some(u32::MAX.into()),
          amount: Some(u64::MAX.into()),
          offset: (Some(u32::MAX.into()), Some(u32::MAX.into())),
          height: (Some(u32::MAX.into()), Some(u32::MAX.into())),
        }),
        turbo: true,
        premine: Some(u64::MAX.into()),
        rune: Some(Rune(u128::MAX)),
        symbol: Some('\u{10FFFF}'),
        spacers: Some(Etching::MAX_SPACERS),
      }),
      89,
    );

    case(
      Vec::new(),
      Some(Etching {
        rune: Some(Rune(u128::MAX)),
        ..default()
      }),
      25,
    );

    case(
      vec![Edict {
        amount: 0,
        id: RuneId { block: 0, tx: 0 },
        output: 0,
      }],
      Some(Etching {
        divisibility: Some(Etching::MAX_DIVISIBILITY),
        rune: Some(Rune(u128::MAX)),
        ..default()
      }),
      32,
    );

    case(
      vec![Edict {
        amount: u128::MAX,
        id: RuneId { block: 0, tx: 0 },
        output: 0,
      }],
      Some(Etching {
        divisibility: Some(Etching::MAX_DIVISIBILITY),
        rune: Some(Rune(u128::MAX)),
        ..default()
      }),
      50,
    );

    case(
      vec![Edict {
        amount: 0,
        id: RuneId {
          block: 1_000_000,
          tx: u32::MAX,
        },
        output: 0,
      }],
      None,
      14,
    );

    case(
      vec![Edict {
        amount: u128::MAX,
        id: RuneId {
          block: 1_000_000,
          tx: u32::MAX,
        },
        output: 0,
      }],
      None,
      32,
    );

    case(
      vec![
        Edict {
          amount: u128::MAX,
          id: RuneId {
            block: 1_000_000,
            tx: u32::MAX,
          },
          output: 0,
        },
        Edict {
          amount: u128::MAX,
          id: RuneId {
            block: 1_000_000,
            tx: u32::MAX,
          },
          output: 0,
        },
      ],
      None,
      54,
    );

    case(
      vec![
        Edict {
          amount: u128::MAX,
          id: RuneId {
            block: 1_000_000,
            tx: u32::MAX,
          },
          output: 0,
        },
        Edict {
          amount: u128::MAX,
          id: RuneId {
            block: 1_000_000,
            tx: u32::MAX,
          },
          output: 0,
        },
        Edict {
          amount: u128::MAX,
          id: RuneId {
            block: 1_000_000,
            tx: u32::MAX,
          },
          output: 0,
        },
      ],
      None,
      76,
    );

    case(
      vec![
        Edict {
          amount: u64::MAX.into(),
          id: RuneId {
            block: 1_000_000,
            tx: u32::MAX,
          },
          output: 0,
        };
        4
      ],
      None,
      62,
    );

    case(
      vec![
        Edict {
          amount: u64::MAX.into(),
          id: RuneId {
            block: 1_000_000,
            tx: u32::MAX,
          },
          output: 0,
        };
        5
      ],
      None,
      75,
    );

    case(
      vec![
        Edict {
          amount: u64::MAX.into(),
          id: RuneId {
            block: 0,
            tx: u32::MAX,
          },
          output: 0,
        };
        5
      ],
      None,
      73,
    );

    case(
      vec![
        Edict {
          amount: 1_000_000_000_000_000_000,
          id: RuneId {
            block: 1_000_000,
            tx: u32::MAX,
          },
          output: 0,
        };
        5
      ],
      None,
      70,
    );
  }

  #[test]
  fn etching_with_term_greater_than_maximum_is_still_an_etching() {
    assert_eq!(
      decipher(&[
        Tag::Flags.into(),
        Flag::Etching.mask(),
        Tag::OffsetEnd.into(),
        u128::from(u64::MAX) + 1,
      ]),
      Artifact::Cenotaph(Cenotaph {
        flaw: Some(Flaw::UnrecognizedEvenTag),
        ..default()
      }),
    );
  }

  #[test]
  fn encipher() {
    #[track_caller]
    fn case(runestone: Runestone, expected: &[u128]) {
      let script_pubkey = runestone.encipher();

      let transaction = Transaction {
        input: Vec::new(),
        output: vec![TxOut {
          script_pubkey,
          value: 0,
        }],
        lock_time: LockTime::ZERO,
        version: 2,
      };

      let Payload::Valid(payload) = Runestone::payload(&transaction).unwrap() else {
        panic!("invalid payload")
      };

      assert_eq!(Runestone::integers(&payload).unwrap(), expected);

      let runestone = {
        let mut edicts = runestone.edicts;
        edicts.sort_by_key(|edict| edict.id);
        Runestone {
          edicts,
          ..runestone
        }
      };

      assert_eq!(
        Runestone::decipher(&transaction).unwrap(),
        Artifact::Runestone(runestone),
      );
    }

    case(Runestone::default(), &[]);

    case(
      Runestone {
        edicts: vec![
          Edict {
            id: RuneId::new(2, 3).unwrap(),
            amount: 1,
            output: 0,
          },
          Edict {
            id: RuneId::new(5, 6).unwrap(),
            amount: 4,
            output: 1,
          },
        ],
        etching: Some(Etching {
          divisibility: Some(7),
          premine: Some(8),
          rune: Some(Rune(9)),
          spacers: Some(10),
          symbol: Some('@'),
          terms: Some(Terms {
            cap: Some(11),
            height: (Some(12), Some(13)),
            amount: Some(14),
            offset: (Some(15), Some(16)),
          }),
          turbo: true,
        }),
        mint: Some(RuneId::new(17, 18).unwrap()),
        pointer: Some(0),
      },
      &[
        Tag::Flags.into(),
        Flag::Etching.mask() | Flag::Terms.mask() | Flag::Turbo.mask(),
        Tag::Rune.into(),
        9,
        Tag::Divisibility.into(),
        7,
        Tag::Spacers.into(),
        10,
        Tag::Symbol.into(),
        '@'.into(),
        Tag::Premine.into(),
        8,
        Tag::Amount.into(),
        14,
        Tag::Cap.into(),
        11,
        Tag::HeightStart.into(),
        12,
        Tag::HeightEnd.into(),
        13,
        Tag::OffsetStart.into(),
        15,
        Tag::OffsetEnd.into(),
        16,
        Tag::Mint.into(),
        17,
        Tag::Mint.into(),
        18,
        Tag::Pointer.into(),
        0,
        Tag::Body.into(),
        2,
        3,
        1,
        0,
        3,
        6,
        4,
        1,
      ],
    );

    case(
      Runestone {
        etching: Some(Etching {
          divisibility: None,
          premine: None,
          rune: Some(Rune(3)),
          spacers: None,
          symbol: None,
          terms: None,
          turbo: false,
        }),
        ..default()
      },
      &[Tag::Flags.into(), Flag::Etching.mask(), Tag::Rune.into(), 3],
    );

    case(
      Runestone {
        etching: Some(Etching {
          divisibility: None,
          premine: None,
          rune: None,
          spacers: None,
          symbol: None,
          terms: None,
          turbo: false,
        }),
        ..default()
      },
      &[Tag::Flags.into(), Flag::Etching.mask()],
    );
  }

  #[test]
  fn runestone_payload_is_chunked() {
    let script = Runestone {
      edicts: vec![
        Edict {
          id: RuneId::default(),
          amount: 0,
          output: 0
        };
        129
      ],
      ..default()
    }
    .encipher();

    assert_eq!(script.instructions().count(), 3);

    let script = Runestone {
      edicts: vec![
        Edict {
          id: RuneId::default(),
          amount: 0,
          output: 0
        };
        130
      ],
      ..default()
    }
    .encipher();

    assert_eq!(script.instructions().count(), 4);
  }

  #[test]
  fn edict_output_greater_than_32_max_produces_cenotaph() {
    assert_eq!(
      decipher(&[Tag::Body.into(), 1, 1, 1, u128::from(u32::MAX) + 1]),
      Artifact::Cenotaph(Cenotaph {
        flaw: Some(Flaw::EdictOutput),
        ..default()
      }),
    );
  }

  #[test]
  fn partial_mint_produces_cenotaph() {
    assert_eq!(
      decipher(&[Tag::Mint.into(), 1]),
      Artifact::Cenotaph(Cenotaph {
        flaw: Some(Flaw::UnrecognizedEvenTag),
        ..default()
      }),
    );
  }

  #[test]
  fn invalid_mint_produces_cenotaph() {
    assert_eq!(
      decipher(&[Tag::Mint.into(), 0, Tag::Mint.into(), 1]),
      Artifact::Cenotaph(Cenotaph {
        flaw: Some(Flaw::UnrecognizedEvenTag),
        ..default()
      }),
    );
  }

  #[test]
  fn invalid_deadline_produces_cenotaph() {
    assert_eq!(
      decipher(&[Tag::OffsetEnd.into(), u128::MAX]),
      Artifact::Cenotaph(Cenotaph {
        flaw: Some(Flaw::UnrecognizedEvenTag),
        ..default()
      }),
    );
  }

  #[test]
  fn invalid_default_output_produces_cenotaph() {
    assert_eq!(
      decipher(&[Tag::Pointer.into(), 1]),
      Artifact::Cenotaph(Cenotaph {
        flaw: Some(Flaw::UnrecognizedEvenTag),
        ..default()
      }),
    );
    assert_eq!(
      decipher(&[Tag::Pointer.into(), u128::MAX]),
      Artifact::Cenotaph(Cenotaph {
        flaw: Some(Flaw::UnrecognizedEvenTag),
        ..default()
      }),
    );
  }

  #[test]
  fn invalid_divisibility_does_not_produce_cenotaph() {
    assert_eq!(
      decipher(&[Tag::Divisibility.into(), u128::MAX]),
      Artifact::Runestone(default()),
    );
  }

  #[test]
  fn min_and_max_runes_are_not_cenotaphs() {
    assert_eq!(
      decipher(&[Tag::Flags.into(), Flag::Etching.into(), Tag::Rune.into(), 0]),
      Artifact::Runestone(Runestone {
        etching: Some(Etching {
          rune: Some(Rune(0)),
          ..default()
        }),
        ..default()
      }),
    );
    assert_eq!(
      decipher(&[
        Tag::Flags.into(),
        Flag::Etching.into(),
        Tag::Rune.into(),
        u128::MAX
      ]),
      Artifact::Runestone(Runestone {
        etching: Some(Etching {
          rune: Some(Rune(u128::MAX)),
          ..default()
        }),
        ..default()
      }),
    );
  }

  #[test]
  fn invalid_spacers_does_not_produce_cenotaph() {
    assert_eq!(
      decipher(&[Tag::Spacers.into(), u128::MAX]),
      Artifact::Runestone(default()),
    );
  }

  #[test]
  fn invalid_symbol_does_not_produce_cenotaph() {
    assert_eq!(
      decipher(&[Tag::Symbol.into(), u128::MAX]),
      Artifact::Runestone(default()),
    );
  }

  #[test]
  fn invalid_term_produces_cenotaph() {
    assert_eq!(
      decipher(&[Tag::OffsetEnd.into(), u128::MAX]),
      Artifact::Cenotaph(Cenotaph {
        flaw: Some(Flaw::UnrecognizedEvenTag),
        ..default()
      }),
    );
  }

  #[test]
  fn invalid_supply_produces_cenotaph() {
    assert_eq!(
      decipher(&[
        Tag::Flags.into(),
        Flag::Etching.mask() | Flag::Terms.mask(),
        Tag::Cap.into(),
        1,
        Tag::Amount.into(),
        u128::MAX
      ]),
      Artifact::Runestone(Runestone {
        etching: Some(Etching {
          terms: Some(Terms {
            cap: Some(1),
            amount: Some(u128::MAX),
            height: (None, None),
            offset: (None, None),
          }),
          ..default()
        }),
        ..default()
      }),
    );

    assert_eq!(
      decipher(&[
        Tag::Flags.into(),
        Flag::Etching.mask() | Flag::Terms.mask(),
        Tag::Cap.into(),
        2,
        Tag::Amount.into(),
        u128::MAX
      ]),
      Artifact::Cenotaph(Cenotaph {
        flaw: Some(Flaw::SupplyOverflow),
        ..default()
      }),
    );

    assert_eq!(
      decipher(&[
        Tag::Flags.into(),
        Flag::Etching.mask() | Flag::Terms.mask(),
        Tag::Cap.into(),
        2,
        Tag::Amount.into(),
        u128::MAX / 2 + 1
      ]),
      Artifact::Cenotaph(Cenotaph {
        flaw: Some(Flaw::SupplyOverflow),
        ..default()
      }),
    );

    assert_eq!(
      decipher(&[
        Tag::Flags.into(),
        Flag::Etching.mask() | Flag::Terms.mask(),
        Tag::Premine.into(),
        1,
        Tag::Cap.into(),
        1,
        Tag::Amount.into(),
        u128::MAX
      ]),
      Artifact::Cenotaph(Cenotaph {
        flaw: Some(Flaw::SupplyOverflow),
        ..default()
      }),
    );
  }

  #[test]
  fn invalid_scripts_in_op_returns_without_magic_number_are_ignored() {
    assert_eq!(
      Runestone::decipher(&Transaction {
        version: 2,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
          previous_output: OutPoint::null(),
          script_sig: ScriptBuf::new(),
          sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
          witness: Witness::new(),
        }],
        output: vec![TxOut {
          script_pubkey: ScriptBuf::from(vec![
            opcodes::all::OP_RETURN.to_u8(),
            opcodes::all::OP_PUSHBYTES_4.to_u8(),
          ]),
          value: 0,
        }],
      }),
      None
    );

    assert_eq!(
      Runestone::decipher(&Transaction {
        version: 2,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
          previous_output: OutPoint::null(),
          script_sig: ScriptBuf::new(),
          sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
          witness: Witness::new(),
        }],
        output: vec![
          TxOut {
            script_pubkey: ScriptBuf::from(vec![
              opcodes::all::OP_RETURN.to_u8(),
              opcodes::all::OP_PUSHBYTES_4.to_u8(),
            ]),
            value: 0,
          },
          TxOut {
            script_pubkey: Runestone::default().encipher(),
            value: 0,
          }
        ],
      })
      .unwrap(),
      Artifact::Runestone(Runestone::default()),
    );
  }

  #[test]
  fn invalid_scripts_in_op_returns_with_magic_number_produce_cenotaph() {
    assert_eq!(
      Runestone::decipher(&Transaction {
        version: 2,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
          previous_output: OutPoint::null(),
          script_sig: ScriptBuf::new(),
          sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
          witness: Witness::new(),
        }],
        output: vec![TxOut {
          script_pubkey: ScriptBuf::from(vec![
            opcodes::all::OP_RETURN.to_u8(),
            Runestone::MAGIC_NUMBER.to_u8(),
            opcodes::all::OP_PUSHBYTES_4.to_u8(),
          ]),
          value: 0,
        }],
      })
      .unwrap(),
      Artifact::Cenotaph(Cenotaph {
        flaw: Some(Flaw::InvalidScript),
        ..default()
      }),
    );
  }

  #[test]
  fn all_pushdata_opcodes_are_valid() {
    for i in 0..79 {
      let mut script_pubkey = Vec::new();

      script_pubkey.push(opcodes::all::OP_RETURN.to_u8());
      script_pubkey.push(Runestone::MAGIC_NUMBER.to_u8());
      script_pubkey.push(i);

      match i {
        0..=75 => {
          for j in 0..i {
            script_pubkey.push(if j % 2 == 0 { 1 } else { 0 });
          }

          if i % 2 == 1 {
            script_pubkey.push(1);
            script_pubkey.push(1);
          }
        }
        76 => {
          script_pubkey.push(0);
        }
        77 => {
          script_pubkey.push(0);
          script_pubkey.push(0);
        }
        78 => {
          script_pubkey.push(0);
          script_pubkey.push(0);
          script_pubkey.push(0);
          script_pubkey.push(0);
        }
        _ => unreachable!(),
      }

      assert_eq!(
        Runestone::decipher(&Transaction {
          version: 2,
          lock_time: LockTime::ZERO,
          input: default(),
          output: vec![TxOut {
            script_pubkey: script_pubkey.into(),
            value: 0,
          },],
        })
        .unwrap(),
        Artifact::Runestone(Runestone::default()),
      );
    }
  }

  #[test]
  fn all_non_pushdata_opcodes_are_invalid() {
    for i in 79..=u8::MAX {
      assert_eq!(
        Runestone::decipher(&Transaction {
          version: 2,
          lock_time: LockTime::ZERO,
          input: default(),
          output: vec![TxOut {
            script_pubkey: vec![
              opcodes::all::OP_RETURN.to_u8(),
              Runestone::MAGIC_NUMBER.to_u8(),
              i
            ]
            .into(),
            value: 0,
          },],
        })
        .unwrap(),
        Artifact::Cenotaph(Cenotaph {
          flaw: Some(Flaw::Opcode),
          ..default()
        }),
      );
    }
  }
}
