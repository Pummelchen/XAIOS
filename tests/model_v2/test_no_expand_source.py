import pathlib
import unittest


class NoExpandKernelSourceTest(unittest.TestCase):
    def test_legacy_packed_kernels_do_not_allocate_matrix_copies(self):
        root = pathlib.Path(__file__).resolve().parents[2]
        source = (root / "kernel/runtime/ai_kernels.c").read_text()

        self.assertNotIn("kheap_alloc", source)
        self.assertNotIn("kheap_free", source)
        self.assertIn("unpack_int4", source)
        self.assertIn("unpack_int6", source)


if __name__ == "__main__":
    unittest.main()
