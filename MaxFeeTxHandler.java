import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.List;

public class MaxFeeTxHandler {

	private UTXOPool utxoPool;

	public MaxFeeTxHandler(UTXOPool utxoPool) {
		this.utxoPool = utxoPool;
	}

	public double calculateTransactionFees(Transaction tx) {
		double inputValues = 0;
		double outputValues = 0;
		for (Transaction.Input i : tx.getInputs()) {
			UTXO u = new UTXO(i.prevTxHash, i.outputIndex);
			if (this.utxoPool.contains(u) && isValidTx(tx)) {
				inputValues += this.utxoPool.getTxOutput(u).value;
			}
		}
		for (Transaction.Output o : tx.getOutputs()) {
			outputValues += o.value;
		}

		return inputValues - outputValues;
	}

	public boolean isValidTx(Transaction tx) {
		List<UTXO> unclaimed = new ArrayList<UTXO>();

		double outputValues = 0;
		double inputValues = 0;

		for (int i = 0; i < tx.numOutputs(); i++) {
			Transaction.Output output = tx.getOutput(i);

			if (output == null || output.value < 0) {
				return false;
			}

			outputValues += output.value;
		}

		for (int i = 0; i < tx.numInputs(); i++) {
			Transaction.Input input = tx.getInput(i);
			if (input == null) {
				return false;
			}

			UTXO u = new UTXO(input.prevTxHash, input.outputIndex);
			if (!this.utxoPool.contains(u) || unclaimed.contains(u)) {
				return false;
			}

			Transaction.Output out = this.utxoPool.getTxOutput(u);
			PublicKey pubkey = out.address;

			if (!Crypto.verifySignature(pubkey, tx.getRawDataToSign(i), input.signature)) {
				return false;
			}

			unclaimed.add(i, u);

			inputValues += out.value;
		}

		return inputValues >= outputValues;
	}

	/**
	 * Handles each epoch by receiving an unordered array of proposed
	 * transactions, checking each transaction for correctness, returning a
	 * mutually valid array of accepted transactions, and updating the current
	 * UTXO pool as appropriate.
	 */
	public Transaction[] handleTxs(Transaction[] possibleTxs) {
		ArrayList<Transaction> validTxs = new ArrayList<>();
		
		Arrays.sort(possibleTxs, new Comparator<Transaction>() {
			@Override
			public int compare(final Transaction a, final Transaction b) {
				double aValues = calculateTransactionFees(a);
				double bValues = calculateTransactionFees(b);
				return (aValues > bValues ? 1 : (bValues > aValues ? -1 : 0));
			}
		});

		for (Transaction tx : possibleTxs) {
			if (isValidTx(tx)) {
				validTxs.add(tx);
				for (int j = 0; j < tx.getInputs().size(); j++) {
					UTXO u = new UTXO(tx.getInput(j).prevTxHash, tx.getInput(j).outputIndex);
					this.utxoPool.removeUTXO(u);
				}

				for (int k = 0; k < tx.getOutputs().size(); k++) {
					UTXO newUTXO = new UTXO(tx.getHash(), k);
					this.utxoPool.addUTXO(newUTXO, tx.getOutput(k));
				}
			}
		}

		return validTxs.toArray(new Transaction[validTxs.size()]);
	}

}
